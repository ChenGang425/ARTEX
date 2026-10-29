package server

import (
	"context"
	"log"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
)

// 阶段 C — asset-scope-exploration-bridge（scope 下发）
//
// ARTEX 把一个 task 的授权范围下发为其 strix 沙箱会话的 scope：task_scope 的
// 域名/网段(直接授权边界) + 该 task 范围内资产的具体主机(域名/IP)，经 MCP 的
// set_scope 工具传给 strix。strix 侧据此在 exec_command/agent_browser 返回里对越界
// 目标附 scope_warning(记录告警、不阻断；硬管控仍在 ARTEX HITL，design D4)。
// 下发受 strix MCP 行 enabled + 新开关 strix_scope_bridge 双重门控、默认关、可独立回滚。

// strixScopeBridgeEnabled reports whether阶段C scope 下发 is on. It requires BOTH
// the strix MCP row enabled (阶段A 主开关) AND the scope-bridge setting, so
// disabling either one reverts cleanly to the native closed loop (design D7).
func (e *Engine) strixScopeBridgeEnabled() *db.MCPServer {
	if e.m == nil || e.m.pg == nil {
		return nil
	}
	if !e.m.pg.GetBool(settingStrixScopeBridge, false) {
		return nil
	}
	return e.strixServerRow()
}

// pushStrixScope gathers the task's authorization range and pushes it to the task's
// strix sandbox session via set_scope. Best-effort + non-blocking at the task-start
// boundary: a disabled feature, an unreachable execution plane or an empty scope all
// just skip without touching the main loop (3.4 降级). Call it after openStrixSession
// so the session usually exists; set_scope stores scope independently of the sandbox
// bundle, so a lingering open race is harmless.
func (e *Engine) pushStrixScope(ctx context.Context, taskID string) {
	m := e.strixScopeBridgeEnabled()
	if m == nil {
		return // feature off
	}
	tid, err := strconv.ParseInt(taskID, 10, 64)
	if err != nil || tid <= 0 {
		return
	}
	targets := e.collectStrixScopeTargets(tid)
	if len(targets) == 0 {
		return // no anchored scope — nothing to constrain
	}
	if _, err := e.strixSyncCall(ctx, m, "set_scope",
		map[string]any{"session_id": taskID, "targets": targets}); err != nil {
		log.Printf("[strix-scope] task %s set_scope 失败: %v", taskID, err)
		return
	}
	log.Printf("[strix-scope] task %s scope 下发 %d 个目标", taskID, len(targets))
}

// collectStrixScopeTargets assembles the scope target list for a task: the explicit
// task_scope authorization edges (domains/CIDRs) plus the concrete in-scope asset
// hosts. The asset-host enrichment is best-effort — its absence only narrows the
// boundary, never breaks the push.
func (e *Engine) collectStrixScopeTargets(tid int64) []string {
	if e.m == nil || e.m.assets == nil {
		return nil
	}
	rows, err := e.m.assets.ListTaskScope(tid)
	if err != nil {
		log.Printf("[strix-scope] task %d 读 task_scope 失败: %v", tid, err)
	}
	targets := taskScopeTargets(rows)
	hosts, err := e.m.assets.InScopeAssetHosts(tid)
	if err != nil {
		log.Printf("[strix-scope] task %d 读范围内资产主机失败: %v", tid, err)
	}
	return mergeScopeTargets(targets, hosts)
}

// taskScopeTargets maps task_scope rows to strix scope entries: root_domain /
// subdomain → the domain; ip / cidr → the CIDR network. company / icp / keyword
// rows carry no host boundary of their own and are covered via the in-scope asset
// hosts instead, so they are skipped here. Order preserved, deduped.
func taskScopeTargets(rows []db.TaskScope) []string {
	out := []string{}
	seen := map[string]bool{}
	add := func(v string) {
		v = strings.TrimSpace(strings.ToLower(v))
		if v == "" || seen[v] {
			return
		}
		seen[v] = true
		out = append(out, v)
	}
	for _, r := range rows {
		switch r.Kind {
		case "root_domain", "subdomain":
			add(r.Domain)
		case "ip", "cidr":
			add(r.Net)
		}
	}
	return out
}

// mergeScopeTargets concatenates two target lists, deduping (case-insensitive) and
// preserving first-seen order.
func mergeScopeTargets(lists ...[]string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, list := range lists {
		for _, v := range list {
			v = strings.TrimSpace(strings.ToLower(v))
			if v == "" || seen[v] {
				continue
			}
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
