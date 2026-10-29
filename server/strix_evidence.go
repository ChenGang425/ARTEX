package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/evidence"
	"github.com/Autumn-27/artex/mcphttp"
)

// 阶段 B — cross-tool-evidence-sync（执行结果回流留证）
//
// strix 执行面产生的 finding 与其 Caido 流量经 MCP 的 export_findings /
// export_traffic 拉回 ARTEX，映射为 ARTEX finding（+ 探索图节点）并把引用的流量快照
// 成内容寻址证据，按 taskID 绑定（design D5/D6）。回流是 finding 驱动的：只有 strix
// 产出 finding 时其引用流量才作为证据落库；strix 流量全程走 Caido、不经 ARTEX
// mitmproxy，故无双抓（5.2）。去重用 strix_finding_sync 的 (task_id, external_id)
// 幂等键，入库后仍由 ARTEX finding-cases 归并裁决（5.5）。

// strixSyncTimeout bounds one export round-trip. Larger than the lifecycle
// timeout because export_traffic may fetch many raw exchanges from Caido; still
// well under the mcphttp client's own 120s HTTP ceiling.
const strixSyncTimeout = 90 * time.Second

// strixEvidenceSyncInterval is the period between best-effort evidence syncs
// while a task runs, so strix products surface in the Web UI exploration graph /
// evidence库 without waiting for task teardown (final sync still runs at close).
const strixEvidenceSyncInterval = 30 * time.Second

// strixFinding is the subset of a strix CVSS finding (reporting/state.py report
// dict, enriched by export_findings with cvss_vector) that ARTEX maps. Unknown
// fields (code_locations, cvss_breakdown, …) are ignored; null JSON values decode
// to the zero value, so partial findings map cleanly.
type strixFinding struct {
	ID                string   `json:"id"`
	Title             string   `json:"title"`
	Severity          string   `json:"severity"`
	CVSS              float64  `json:"cvss"`
	CVSSVector        string   `json:"cvss_vector"`
	Description       string   `json:"description"`
	Impact            string   `json:"impact"`
	Target            string   `json:"target"`
	TechnicalAnalysis string   `json:"technical_analysis"`
	PocDescription    string   `json:"poc_description"`
	PocScriptCode     string   `json:"poc_script_code"`
	Evidence          string   `json:"evidence"`
	Remediation       string   `json:"remediation_steps"`
	Endpoint          string   `json:"endpoint"`
	Method            string   `json:"method"`
	CVE               string   `json:"cve"`
	CWE               string   `json:"cwe"`
	FindingClass      string   `json:"finding_class"`
	AgentName         string   `json:"agent_name"`
	HTTPExchangeIDs   []string `json:"http_exchange_ids"`
}

// strixTrafficExchange is one exchange from export_traffic (see strix
// mcp_server._exchange_payload).
type strixTrafficExchange struct {
	ID          string `json:"id"`
	URL         string `json:"url"`
	Method      string `json:"method"`
	Status      int    `json:"status"`
	ContentType string `json:"content_type"`
	CapturedAt  int64  `json:"captured_at"`
	RequestRaw  string `json:"request_raw"`
	ResponseRaw string `json:"response_raw"`
}

func (e *Engine) engineEvidenceStore() *evidence.Store {
	return evidence.New(e.m.pg, e.m.traffic, filepath.Join(e.m.dir, "evidence"))
}

// strixEvidenceSyncEnabled reports whether阶段B回流 is on. It requires BOTH the
// strix MCP row enabled (阶段A 主开关) AND the evidence-sync setting, so disabling
// either one cleanly reverts to the native closed loop (design D7).
func (e *Engine) strixEvidenceSyncEnabled() *db.MCPServer {
	if e.m == nil || e.m.pg == nil {
		return nil
	}
	if !e.m.pg.GetBool(settingStrixEvidenceSync, false) {
		return nil
	}
	return e.strixServerRow()
}

// strixEvidenceSyncLoop periodically syncs a running task's strix evidence. It is
// a best-effort background goroutine bound to the task's context: an unreachable
// execution plane only means this round is skipped (3.4 降级), never a stalled
// loop. Exits when the task context is cancelled (StopTask).
func (e *Engine) strixEvidenceSyncLoop(ctx context.Context, taskID string) {
	if e.strixEvidenceSyncEnabled() == nil {
		return // feature off — no goroutine churn
	}
	ticker := time.NewTicker(strixEvidenceSyncInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.syncStrixEvidence(ctx, taskID)
		}
	}
}

// finalStrixEvidenceSync runs one last sync before the sandbox container (and its
// Caido history) is reclaimed at teardown, so no confirmed product is lost. Uses a
// fresh background context because the task context is torn down concurrently.
func (e *Engine) finalStrixEvidenceSync(taskID string) {
	if e.strixEvidenceSyncEnabled() == nil {
		return
	}
	e.syncStrixEvidence(context.Background(), taskID)
}

// syncStrixEvidence pulls strix findings for the task, maps each not-yet-synced
// one into an ARTEX finding, and binds its referenced Caido exchanges as evidence.
// Every step is best-effort and isolated: a single bad finding is logged and
// skipped, never aborting the whole round.
func (e *Engine) syncStrixEvidence(ctx context.Context, taskID string) {
	m := e.strixEvidenceSyncEnabled()
	if m == nil {
		return
	}
	tid, err := strconv.ParseInt(taskID, 10, 64)
	if err != nil || tid <= 0 {
		return
	}
	var expID int64
	if err := e.m.pg.QueryRow(`SELECT exploration_id FROM tasks WHERE id=$1`, tid).Scan(&expID); err != nil {
		if err != sql.ErrNoRows {
			log.Printf("[strix-sync] task %s 取探索记录失败: %v", taskID, err)
		}
		return
	}
	findings, err := e.strixExportFindings(ctx, m, taskID)
	if err != nil {
		log.Printf("[strix-sync] task %s export_findings 失败: %v", taskID, err)
		return
	}
	if len(findings) == 0 {
		return
	}
	synced, err := e.m.pg.StrixSyncedExternalIDs(ctx, tid)
	if err != nil {
		log.Printf("[strix-sync] task %s 读同步表失败: %v", taskID, err)
		return
	}
	store := e.engineEvidenceStore()
	for _, f := range findings {
		if f.ID == "" || synced[f.ID] != 0 {
			continue // unidentifiable or already reflected into ARTEX
		}
		if err := e.syncOneStrixFinding(ctx, store, m, taskID, tid, expID, f); err != nil {
			log.Printf("[strix-sync] task %s finding %s 回流失败: %v", taskID, f.ID, err)
		}
	}
}

func (e *Engine) syncOneStrixFinding(ctx context.Context, store *evidence.Store, m *db.MCPServer, taskID string, tid, expID int64, f strixFinding) error {
	var exchanges []evidence.ExternalExchange
	if len(f.HTTPExchangeIDs) > 0 {
		raw, err := e.strixExportTraffic(ctx, m, taskID, f.HTTPExchangeIDs)
		if err != nil {
			// Traffic是尽力而为的证据补充:拉不到就先落 finding(仍带文字/PoC 证据),
			// 下一轮或复查再补绑,不因流量缺失丢掉已确认的 finding。
			log.Printf("[strix-sync] task %s finding %s export_traffic 失败(仅文字证据入库): %v", taskID, f.ID, err)
		} else {
			exchanges = raw
		}
	}
	in := mapStrixFinding(f, tid, expID)
	_, err := store.RecordExternal(ctx, in, exchanges, func(tx *sql.Tx, rf *db.RecordedFinding) error {
		return db.MarkStrixFindingSyncedTx(ctx, tx, db.StrixSyncedFinding{TaskID: tid, ExternalID: f.ID, FindingID: rf.FindingID})
	})
	return err
}

// strixExportFindings / strixExportTraffic call the MCP export tools and parse
// their structured JSON envelopes.
func (e *Engine) strixExportFindings(ctx context.Context, m *db.MCPServer, taskID string) ([]strixFinding, error) {
	raw, err := e.strixSyncCall(ctx, m, "export_findings", map[string]any{"session_id": taskID})
	if err != nil {
		return nil, err
	}
	var env struct {
		Success  bool           `json:"success"`
		Error    string         `json:"error"`
		Findings []strixFinding `json:"findings"`
	}
	if err := json.Unmarshal([]byte(raw), &env); err != nil {
		return nil, fmt.Errorf("export_findings 返回解析失败: %w", err)
	}
	if !env.Success {
		return nil, fmt.Errorf("export_findings 失败: %s", env.Error)
	}
	return env.Findings, nil
}

func (e *Engine) strixExportTraffic(ctx context.Context, m *db.MCPServer, taskID string, requestIDs []string) ([]evidence.ExternalExchange, error) {
	raw, err := e.strixSyncCall(ctx, m, "export_traffic", map[string]any{"session_id": taskID, "request_ids": requestIDs})
	if err != nil {
		return nil, err
	}
	var env struct {
		Success   bool                   `json:"success"`
		Error     string                 `json:"error"`
		Exchanges []strixTrafficExchange `json:"exchanges"`
	}
	if err := json.Unmarshal([]byte(raw), &env); err != nil {
		return nil, fmt.Errorf("export_traffic 返回解析失败: %w", err)
	}
	if !env.Success {
		return nil, fmt.Errorf("export_traffic 失败: %s", env.Error)
	}
	return strixExchangesToExternal(env.Exchanges), nil
}

// strixExchangesToExternal maps export_traffic exchanges to evidence exchanges,
// tagging each with a "strix:" provenance id and the "proof" role (a finding's
// referenced exchanges are its proof).
func strixExchangesToExternal(exchanges []strixTrafficExchange) []evidence.ExternalExchange {
	out := make([]evidence.ExternalExchange, 0, len(exchanges))
	for _, x := range exchanges {
		out = append(out, evidence.ExternalExchange{
			SourceID:    "strix:" + x.ID,
			CapturedAt:  x.CapturedAt,
			URL:         x.URL,
			Method:      x.Method,
			Status:      x.Status,
			ContentType: x.ContentType,
			Request:     []byte(x.RequestRaw),
			Response:    []byte(x.ResponseRaw),
			Role:        "proof",
		})
	}
	return out
}

// strixSyncCall dials the strix MCP server and invokes an export tool, returning
// its raw JSON text. Backend orchestration call — bypasses the agent permission
// layer, same intent as strixSessionCall.
func (e *Engine) strixSyncCall(ctx context.Context, m *db.MCPServer, tool string, args map[string]any) (string, error) {
	callCtx, cancel := context.WithTimeout(ctx, strixSyncTimeout)
	defer cancel()
	cl, err := connectMCP(callCtx, m)
	if err != nil {
		return "", err
	}
	defer func() { _ = cl.Close() }()
	hc, ok := cl.(*mcphttp.Client)
	if !ok {
		return "", fmt.Errorf("strix MCP 非 http transport")
	}
	return hc.Call(callCtx, tool, args)
}

// mapStrixFinding is the strix CVSS finding → ARTEX finding-cases field mapping
// (task 5.4). ARTEX findings carry no CVSS column (design non-goal: no schema
// change), so the CVSS score/vector and all supporting detail land in the
// evidence text; title/severity/scope map to first-class columns.
func mapStrixFinding(f strixFinding, taskID, expID int64) db.RecordFindingInput {
	vulnClass := strings.TrimSpace(f.CWE)
	if vulnClass == "" {
		vulnClass = strings.TrimSpace(f.FindingClass)
	}
	summary := clipText(firstNonEmpty(f.Description, f.Impact, f.Title), 2000)
	worker := "strix"
	if a := strings.TrimSpace(f.AgentName); a != "" {
		worker = "strix:" + a
	}
	return db.RecordFindingInput{
		TaskID:        taskID,
		ExplorationID: expID,
		VulnClass:     clipText(vulnClass, 200),
		Name:          clipText(strings.TrimSpace(f.Title), 500),
		Severity:      mapStrixSeverity(f.Severity),
		Summary:       summary,
		Evidence:      strixEvidenceText(f),
		Worker:        worker,
	}
}

// mapStrixSeverity maps strix severities (critical/high/medium/low/info) to
// ARTEX's set (critical/high/medium/low); informational/none collapse to low.
func mapStrixSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	default:
		return "low"
	}
}

// strixEvidenceText assembles the finding's detail (incl. the CVSS score/vector)
// into one Markdown block for ARTEX's evidence column. Empty sections are omitted.
func strixEvidenceText(f strixFinding) string {
	var b strings.Builder
	addLine := func(label, value string) {
		if v := strings.TrimSpace(value); v != "" {
			fmt.Fprintf(&b, "**%s:** %s\n\n", label, v)
		}
	}
	addBlock := func(label, value string) {
		if v := strings.TrimSpace(value); v != "" {
			fmt.Fprintf(&b, "**%s:**\n\n%s\n\n", label, v)
		}
	}
	if f.CVSS > 0 || f.CVSSVector != "" {
		cvss := strings.TrimSpace(f.CVSSVector)
		if f.CVSS > 0 {
			if cvss != "" {
				cvss = fmt.Sprintf("%.1f (%s)", f.CVSS, cvss)
			} else {
				cvss = fmt.Sprintf("%.1f", f.CVSS)
			}
		}
		addLine("CVSS", cvss)
	}
	addLine("Target", f.Target)
	if ep := strings.TrimSpace(f.Endpoint); ep != "" {
		addLine("Endpoint", strings.TrimSpace(f.Method+" "+ep))
	}
	addLine("CVE", f.CVE)
	addLine("CWE", f.CWE)
	addBlock("Impact", f.Impact)
	addBlock("Technical analysis", f.TechnicalAnalysis)
	addBlock("PoC", f.PocDescription)
	if code := strings.TrimSpace(f.PocScriptCode); code != "" {
		fmt.Fprintf(&b, "**PoC script:**\n\n```\n%s\n```\n\n", code)
	}
	addBlock("Evidence", f.Evidence)
	addBlock("Remediation", f.Remediation)
	if len(f.HTTPExchangeIDs) > 0 {
		addLine("Caido exchanges", strings.Join(f.HTTPExchangeIDs, ", "))
	}
	return strings.TrimSpace(b.String())
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}

func clipText(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}
