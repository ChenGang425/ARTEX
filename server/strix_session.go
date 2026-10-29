package server

import (
	"context"
	"encoding/json"
	"log"
	"strconv"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/mcphttp"
	actool "github.com/Autumn-27/norma/tool"
)

// strixMCPServerName is the seeded MCP server row (db/db.go) exposing strix's Kali
// sandbox as mcp__strix__*. It is disabled by default: enabling that row IS the
// 阶段A feature flag (design D7). When disabled, none of the helpers below do
// anything, so ARTEX falls back to its native tool closure with zero impact.
const strixMCPServerName = "strix"

// strixSessionTimeout bounds the open/close MCP round-trips so a slow or
// unreachable sandbox never stalls task start/teardown (design risk: Go↔Python
// network链路; 3.4 降级).
const strixSessionTimeout = 30 * time.Second

// strixSessionID derives the strix session_id for the current run from the task
// id carried in RunInfo. It matches the engine's string task id
// (strconv.FormatInt(taskID,10)) used by openStrixSession/closeStrixSession, so a
// tool call and its sandbox lifecycle always share one session. Empty = no task
// binding (e.g. a chat run); callers skip injection then.
func strixSessionID(ctx context.Context) string {
	if ri := agent.RunInfoFrom(ctx); ri.TaskID > 0 {
		return strconv.FormatInt(ri.TaskID, 10)
	}
	return ""
}

// injectStrixSession wraps a strix MCP tool so the ARTEX task's session_id is
// bound transparently: the model never sees or supplies session_id (it is an
// orchestration detail), and the engine guarantees the matching sandbox session
// exists (openStrixSession). The wrapper strips session_id from the advertised
// schema and injects it into the arguments right before the real call. When
// sessionID is empty (non-task run) the tool passes through unchanged and strix
// returns its "session not found" error — a graceful, visible failure.
func injectStrixSession(inner actool.CoreTool, sessionID string) actool.CoreTool {
	if sessionID == "" {
		return inner
	}
	return actool.Build(actool.Spec{
		Name:        inner.Name(),
		Description: inner.Description(),
		Prompt:      inner.Prompt(),
		Schema:      schemaWithoutSessionID(inner.InputSchema()),
		ReadOnly:    func(in json.RawMessage) bool { return inner.IsReadOnly(in) },
		Concurrent:  func(in json.RawMessage) bool { return inner.IsConcurrencySafe(in) },
		Permissions: inner.CheckPermissions,
		Run: func(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
			return inner.Call(ctx, withSessionID(in, sessionID), tc)
		},
	})
}

// schemaWithoutSessionID returns a copy of schema with session_id removed from
// both properties and the required list, so the model is never asked for it.
func schemaWithoutSessionID(schema map[string]any) map[string]any {
	out := make(map[string]any, len(schema))
	for k, v := range schema {
		out[k] = v
	}
	if props, ok := out["properties"].(map[string]any); ok {
		cp := make(map[string]any, len(props))
		for k, v := range props {
			if k == "session_id" {
				continue
			}
			cp[k] = v
		}
		out["properties"] = cp
	}
	if req, ok := out["required"].([]any); ok {
		var cp []any
		for _, r := range req {
			if s, _ := r.(string); s == "session_id" {
				continue
			}
			cp = append(cp, r)
		}
		out["required"] = cp
	}
	return out
}

// withSessionID returns in with session_id set to the bound value. A malformed or
// empty object becomes {"session_id":...} so the call still reaches the sandbox.
func withSessionID(in json.RawMessage, sessionID string) json.RawMessage {
	args := map[string]any{}
	if len(in) > 0 {
		_ = json.Unmarshal(in, &args)
	}
	args["session_id"] = sessionID
	raw, err := json.Marshal(args)
	if err != nil {
		return in
	}
	return raw
}

// strixServerRow returns the enabled strix MCP server row, or nil when the row is
// absent/disabled (feature off) — in which case the whole integration is a no-op.
func (e *Engine) strixServerRow() *db.MCPServer {
	if e.m == nil || e.m.pg == nil {
		return nil
	}
	all, err := e.m.pg.ListMCP()
	if err != nil {
		return nil
	}
	for _, m := range all {
		if m.Name == strixMCPServerName && m.Enabled {
			return m
		}
	}
	return nil
}

// openStrixSession asks strix to create (or reuse) the sandbox session bound to a
// task, at task-start boundary. Best-effort and non-blocking: any failure is
// logged and the main loop continues (3.4 — execution-plane unreachable must not
// break the closed loop; the first exec_command would then surface the error).
func (e *Engine) openStrixSession(ctx context.Context, taskID string) {
	m := e.strixServerRow()
	if m == nil {
		return // feature disabled
	}
	e.strixSessionCall(ctx, m, "open_session", taskID)
}

// closeStrixSession asks strix to reclaim the task's sandbox container at teardown.
func (e *Engine) closeStrixSession(taskID string) {
	m := e.strixServerRow()
	if m == nil {
		return
	}
	e.strixSessionCall(context.Background(), m, "close_session", taskID)
}

// strixSessionCall dials the strix MCP server and invokes a lifecycle tool with the
// task's session_id, bypassing the agent permission layer (this is backend
// orchestration, not a model-issued call — mirrors mcphttp.Client.Call's intent).
func (e *Engine) strixSessionCall(ctx context.Context, m *db.MCPServer, tool, sessionID string) {
	callCtx, cancel := context.WithTimeout(ctx, strixSessionTimeout)
	defer cancel()
	cl, err := connectMCP(callCtx, m)
	if err != nil {
		log.Printf("[strix] %s 连接失败 (session=%s): %v", tool, sessionID, err)
		return
	}
	defer func() { _ = cl.Close() }()
	hc, ok := cl.(*mcphttp.Client)
	if !ok {
		log.Printf("[strix] %s 跳过：strix MCP 非 http transport", tool)
		return
	}
	if _, err := hc.Call(callCtx, tool, map[string]any{"session_id": sessionID}); err != nil {
		log.Printf("[strix] %s 失败 (session=%s): %v", tool, sessionID, err)
	}
}
