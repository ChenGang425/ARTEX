package server

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

func TestStrixSessionIDFromRunInfo(t *testing.T) {
	if got := strixSessionID(context.Background()); got != "" {
		t.Fatalf("no task binding should yield empty session id, got %q", got)
	}
	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: 42})
	if got := strixSessionID(ctx); got != "42" {
		t.Fatalf("session id must match engine task id string, got %q", got)
	}
}

func TestSchemaWithoutSessionID(t *testing.T) {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"session_id": map[string]any{"type": "string"},
			"cmd":        map[string]any{"type": "string"},
		},
		"required": []any{"session_id", "cmd"},
	}
	out := schemaWithoutSessionID(schema)
	props := out["properties"].(map[string]any)
	if _, ok := props["session_id"]; ok {
		t.Fatal("session_id must be hidden from the model-facing schema")
	}
	if _, ok := props["cmd"]; !ok {
		t.Fatal("other properties must be preserved")
	}
	for _, r := range out["required"].([]any) {
		if r == "session_id" {
			t.Fatal("session_id must be dropped from required")
		}
	}
	// original schema must not be mutated
	if _, ok := schema["properties"].(map[string]any)["session_id"]; !ok {
		t.Fatal("input schema was mutated")
	}
}

func TestWithSessionID(t *testing.T) {
	// injects into an existing object without clobbering other args
	raw := withSessionID(json.RawMessage(`{"cmd":"nmap -sV t"}`), "7")
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m["session_id"] != "7" || m["cmd"] != "nmap -sV t" {
		t.Fatalf("unexpected args: %v", m)
	}
	// empty/malformed input still yields a valid session-bound object
	raw = withSessionID(nil, "9")
	m = nil
	if err := json.Unmarshal(raw, &m); err != nil || m["session_id"] != "9" {
		t.Fatalf("empty input should become session object, got %s err=%v", raw, err)
	}
}

// fakeTool is a minimal CoreTool recording the args its Call receives.
type fakeTool struct {
	name   string
	schema map[string]any
	gotIn  json.RawMessage
}

func (f *fakeTool) Name() string                           { return f.name }
func (f *fakeTool) Description() string                    { return "d" }
func (f *fakeTool) Prompt() string                         { return "" }
func (f *fakeTool) InputSchema() map[string]any            { return f.schema }
func (f *fakeTool) IsReadOnly(json.RawMessage) bool        { return false }
func (f *fakeTool) IsConcurrencySafe(json.RawMessage) bool { return false }
func (f *fakeTool) CheckPermissions(context.Context, json.RawMessage, permission.Context) permission.Decision {
	return permission.AskUser("?")
}
func (f *fakeTool) Call(_ context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
	f.gotIn = in
	return actool.Result{}, nil
}

func TestInjectStrixSession(t *testing.T) {
	inner := &fakeTool{
		name: "mcp__strix__exec_command",
		schema: map[string]any{
			"type":       "object",
			"properties": map[string]any{"session_id": map[string]any{}, "cmd": map[string]any{}},
			"required":   []any{"session_id", "cmd"},
		},
	}
	wrapped := injectStrixSession(inner, "100")
	if wrapped.Name() != inner.name {
		t.Fatalf("name must be preserved for visibility bookkeeping, got %q", wrapped.Name())
	}
	if _, ok := wrapped.InputSchema()["properties"].(map[string]any)["session_id"]; ok {
		t.Fatal("wrapped schema must hide session_id")
	}
	if _, err := wrapped.Call(context.Background(), json.RawMessage(`{"cmd":"id"}`), nil); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	_ = json.Unmarshal(inner.gotIn, &got)
	if got["session_id"] != "100" || got["cmd"] != "id" {
		t.Fatalf("inner call did not receive injected session_id: %v", got)
	}

	// empty session id → pass-through (no wrapping)
	if injectStrixSession(inner, "") != actool.CoreTool(inner) {
		t.Fatal("empty session id must return the inner tool unchanged")
	}
}
