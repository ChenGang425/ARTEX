package server

import (
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
)

// 阶段 C — asset-scope-exploration-bridge（探索意图 → strix 子 agent，方案 A 前向兼容接缝）
//
// ARTEX 的可并行探索意图(db.IntentAssets，按意图锚定资产) 映射为 strix 的
// create_agent 子 agent 规格：每个意图一个专精子 agent，锚定资产作为其目标。实际派生
// 由 Worker 调用 mcp__strix__spawn_subagent 发起——该调用经 ARTEX guard 以父 task 为粒度
// 审批(6.4，design D4)，子 agent 的内部动作通过"批准这次 spawn"一次性授权、不再逐个回
// ARTEX 过闸。strix 侧有 per-session agent runtime 时真派生、否则返回 deferred(方案 A)，
// 结果回流复用阶段B export_findings。整体受 strix MCP 行 enabled + strix_subagent_bridge
// 双重门控、默认关、可独立回滚(design D7)。

// strixSpawnSubagentTool is the discovered-tool name of strix's spawn_subagent
// (mcphttp maps bare names to mcp__<server>__<tool>). Gated out of the Worker
// toolset at assembly time unless strix_subagent_bridge is on.
const strixSpawnSubagentTool = "mcp__strix__spawn_subagent"

// strixSubagentSpec is one parallel-intent → child-agent mapping: a specialist to
// spawn for an exploration intent, carrying its anchored asset targets.
type strixSubagentSpec struct {
	IntentID int64    `json:"intent_id"`
	Name     string   `json:"name"`
	Task     string   `json:"task"`
	Targets  []string `json:"targets"`
}

// strixSubagentBridgeEnabled reports whether阶段C 子 agent 接缝 is on. Requires BOTH
// the strix MCP row enabled (阶段A 主开关) AND the subagent-bridge setting, so
// disabling either reverts cleanly (design D7).
func (e *Engine) strixSubagentBridgeEnabled() *db.MCPServer {
	if e.m == nil || e.m.pg == nil {
		return nil
	}
	if !e.m.pg.GetBool(settingStrixSubagentBridge, false) {
		return nil
	}
	return e.strixServerRow()
}

// buildStrixSubagentSpecs maps parallel exploration intents to one child-agent spec
// per intent. Intents are grouped by IntentID (first-seen order preserved); each
// spec's task text summarizes the intent and lists its anchored asset targets, which
// the Worker passes to mcp__strix__spawn_subagent. Inherited (cross-task) intents
// are skipped — only the task's own local intents are parallelizable here.
func buildStrixSubagentSpecs(intents []db.IntentAsset) []strixSubagentSpec {
	order := []int64{}
	byIntent := map[int64]*strixSubagentSpec{}
	summaries := map[int64]string{}
	for _, ia := range intents {
		if ia.Inherited {
			continue
		}
		spec, ok := byIntent[ia.IntentID]
		if !ok {
			spec = &strixSubagentSpec{IntentID: ia.IntentID}
			byIntent[ia.IntentID] = spec
			order = append(order, ia.IntentID)
			summaries[ia.IntentID] = strings.TrimSpace(ia.SourceSummary)
		}
		if label := strings.TrimSpace(ia.Label); label != "" {
			if !containsStr(spec.Targets, label) {
				spec.Targets = append(spec.Targets, label)
			}
		}
	}
	out := make([]strixSubagentSpec, 0, len(order))
	for _, id := range order {
		spec := byIntent[id]
		spec.Name = fmt.Sprintf("intent-%d specialist", id)
		summary := summaries[id]
		if summary == "" {
			summary = "探索该意图锚定的目标"
		}
		task := fmt.Sprintf("探索意图 #%d：%s", id, summary)
		if len(spec.Targets) > 0 {
			task += "；目标：" + strings.Join(spec.Targets, ", ")
		}
		spec.Task = task
		out = append(out, *spec)
	}
	return out
}

func containsStr(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

// logStrixParallelIntents derives the parallel-intent → subagent mapping for a task
// and records it, so the intent→子agent bridge is observable at task start even
// while真派生 is Worker-driven (方案 A). Best-effort + non-blocking: a disabled
// feature or an empty intent set just skips. It never auto-spawns — spawning stays a
// guard-gated Worker tool call (6.4).
func (e *Engine) logStrixParallelIntents(taskID string) {
	if e.strixSubagentBridgeEnabled() == nil {
		return // feature off
	}
	tid, err := strconv.ParseInt(taskID, 10, 64)
	if err != nil || tid <= 0 || e.m == nil || e.m.assets == nil {
		return
	}
	intents, err := e.m.assets.IntentAssets(tid)
	if err != nil {
		log.Printf("[strix-subagent] task %s 读探索意图失败: %v", taskID, err)
		return
	}
	specs := buildStrixSubagentSpecs(intents)
	if len(specs) == 0 {
		return
	}
	names := make([]string, 0, len(specs))
	for _, s := range specs {
		names = append(names, s.Name)
	}
	log.Printf("[strix-subagent] task %s 可并行探索意图映射为 %d 个子 agent: %s",
		taskID, len(specs), strings.Join(names, ", "))
}
