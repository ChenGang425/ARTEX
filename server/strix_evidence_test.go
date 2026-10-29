package server

import (
	"encoding/json"
	"strings"
	"testing"
)

// 阶段 B — strix finding → ARTEX finding 字段映射 (task 5.4) 的纯函数测试,不依赖 PG。

func TestMapStrixSeverity(t *testing.T) {
	cases := map[string]string{
		"critical":      "critical",
		"High":          "high",
		" medium ":      "medium",
		"low":           "low",
		"info":          "low",
		"informational": "low",
		"none":          "low",
		"":              "low",
		"weird":         "low",
	}
	for in, want := range cases {
		if got := mapStrixSeverity(in); got != want {
			t.Errorf("mapStrixSeverity(%q)=%q want %q", in, got, want)
		}
	}
}

func TestMapStrixFindingFieldMapping(t *testing.T) {
	f := strixFinding{
		ID:              "vuln-0007",
		Title:           "SQL Injection in login",
		Severity:        "critical",
		CVSS:            9.8,
		CVSSVector:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		Description:     "User input flows unsanitized into a SQL query.",
		Impact:          "Full DB read/write.",
		Target:          "https://app.example.com",
		Endpoint:        "/api/login",
		Method:          "POST",
		CWE:             "CWE-89",
		CVE:             "CVE-2026-1234",
		PocDescription:  "Send ' OR 1=1-- as username.",
		PocScriptCode:   "curl -d \"user=' OR 1=1--\" https://app/login",
		Evidence:        "Response differs on boolean payloads.",
		Remediation:     "Use parameterized queries.",
		AgentName:       "web-tester",
		HTTPExchangeIDs: []string{"c-1", "c-2"},
	}
	in := mapStrixFinding(f, 42, 7)

	if in.TaskID != 42 || in.ExplorationID != 7 {
		t.Fatalf("task/exploration ids: %+v", in)
	}
	if in.Name != "SQL Injection in login" {
		t.Errorf("name=%q", in.Name)
	}
	if in.Severity != "critical" {
		t.Errorf("severity=%q", in.Severity)
	}
	if in.VulnClass != "CWE-89" { // CWE preferred over finding_class
		t.Errorf("vulnclass=%q", in.VulnClass)
	}
	if in.Worker != "strix:web-tester" {
		t.Errorf("worker=%q", in.Worker)
	}
	if !strings.Contains(in.Summary, "unsanitized") {
		t.Errorf("summary=%q", in.Summary)
	}
	// CVSS score + vector must land in the evidence text (no CVSS column on findings).
	for _, want := range []string{"9.8", "CVSS:3.1/AV:N", "CVE-2026-1234", "CWE-89", "POST /api/login", "parameterized", "c-1, c-2", "' OR 1=1"} {
		if !strings.Contains(in.Evidence, want) {
			t.Errorf("evidence missing %q:\n%s", want, in.Evidence)
		}
	}
}

func TestMapStrixFindingFallbacks(t *testing.T) {
	// No CWE → finding_class; no description → impact → title for summary; no agent → "strix".
	f := strixFinding{
		ID:           "vuln-1",
		Title:        "Title only",
		Severity:     "info",
		FindingClass: "dynamic",
		Impact:       "impact text",
	}
	in := mapStrixFinding(f, 1, 1)
	if in.VulnClass != "dynamic" {
		t.Errorf("vulnclass=%q", in.VulnClass)
	}
	if in.Severity != "low" {
		t.Errorf("severity=%q", in.Severity)
	}
	if in.Worker != "strix" {
		t.Errorf("worker=%q", in.Worker)
	}
	if in.Summary != "impact text" {
		t.Errorf("summary=%q", in.Summary)
	}
}

func TestStrixEvidenceTextOmitsEmptySections(t *testing.T) {
	f := strixFinding{ID: "vuln-2", Title: "t", Severity: "low"}
	out := strixEvidenceText(f)
	if strings.Contains(out, "CVSS") || strings.Contains(out, "PoC") || strings.Contains(out, "Impact") {
		t.Errorf("empty finding produced sections: %q", out)
	}
}

func TestStrixExchangesToExternal(t *testing.T) {
	raw := `{"success":true,"exchanges":[
	 {"id":"c-1","url":"https://app/login","method":"POST","status":200,"content_type":"text/html","captured_at":111,"request_raw":"POST /login HTTP/1.1\r\n\r\nx","response_raw":"HTTP/1.1 200 OK\r\n\r\nok"}
	]}`
	var env struct {
		Exchanges []strixTrafficExchange `json:"exchanges"`
	}
	if err := json.Unmarshal([]byte(raw), &env); err != nil {
		t.Fatal(err)
	}
	ext := strixExchangesToExternal(env.Exchanges)
	if len(ext) != 1 {
		t.Fatalf("len=%d", len(ext))
	}
	e := ext[0]
	if e.SourceID != "strix:c-1" {
		t.Errorf("source=%q", e.SourceID)
	}
	if e.Role != "proof" {
		t.Errorf("role=%q", e.Role)
	}
	if e.Method != "POST" || e.Status != 200 || e.ContentType != "text/html" || e.CapturedAt != 111 {
		t.Errorf("meta=%+v", e)
	}
	if string(e.Request) == "" || string(e.Response) == "" {
		t.Errorf("raw bytes empty: %+v", e)
	}
}

func TestClipText(t *testing.T) {
	if got := clipText("abcdef", 3); got != "abc" {
		t.Errorf("clip=%q", got)
	}
	if got := clipText("ab", 5); got != "ab" {
		t.Errorf("clip=%q", got)
	}
}
