package server

import (
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// 阶段 C — 探索意图 → strix 子 agent 规格映射 (task 6.3) 的纯函数测试,不依赖 PG。

func TestBuildStrixSubagentSpecs(t *testing.T) {
	intents := []db.IntentAsset{
		{IntentID: 10, Label: "https://a.example.com", SourceSummary: "测试登录面"},
		{IntentID: 10, Label: "https://a.example.com", SourceSummary: "测试登录面"}, // dup target
		{IntentID: 10, Label: "https://a.example.com/admin", SourceSummary: "测试登录面"},
		{IntentID: 7, Label: "10.0.0.5", SourceSummary: "探测服务"},
		{IntentID: 99, Label: "inherited.example.com", SourceSummary: "x", Inherited: true}, // skipped
	}
	specs := buildStrixSubagentSpecs(intents)
	if len(specs) != 2 {
		t.Fatalf("want 2 specs, got %d: %+v", len(specs), specs)
	}
	// Order preserved by first-seen intent id (10 before 7).
	if specs[0].IntentID != 10 || specs[1].IntentID != 7 {
		t.Fatalf("order=%d,%d", specs[0].IntentID, specs[1].IntentID)
	}
	s0 := specs[0]
	if s0.Name != "intent-10 specialist" {
		t.Errorf("name=%q", s0.Name)
	}
	if len(s0.Targets) != 2 { // dup collapsed
		t.Errorf("targets=%v", s0.Targets)
	}
	for _, want := range []string{"#10", "测试登录面", "https://a.example.com", "https://a.example.com/admin"} {
		if !strings.Contains(s0.Task, want) {
			t.Errorf("task missing %q: %s", want, s0.Task)
		}
	}
}

func TestBuildStrixSubagentSpecsEmptyAndInheritedOnly(t *testing.T) {
	if got := buildStrixSubagentSpecs(nil); len(got) != 0 {
		t.Errorf("nil → want empty, got %v", got)
	}
	inheritedOnly := []db.IntentAsset{
		{IntentID: 1, Label: "x.example.com", Inherited: true},
	}
	if got := buildStrixSubagentSpecs(inheritedOnly); len(got) != 0 {
		t.Errorf("inherited-only → want empty, got %v", got)
	}
}

func TestBuildStrixSubagentSpecsDefaultSummary(t *testing.T) {
	// No source summary → a default task description is used.
	intents := []db.IntentAsset{{IntentID: 5, Label: "svc.example.com"}}
	specs := buildStrixSubagentSpecs(intents)
	if len(specs) != 1 {
		t.Fatalf("len=%d", len(specs))
	}
	if !strings.Contains(specs[0].Task, "探索该意图锚定的目标") {
		t.Errorf("default summary missing: %s", specs[0].Task)
	}
	if !strings.Contains(specs[0].Task, "svc.example.com") {
		t.Errorf("target missing: %s", specs[0].Task)
	}
}

func TestContainsStr(t *testing.T) {
	if !containsStr([]string{"a", "b"}, "b") {
		t.Error("want true")
	}
	if containsStr([]string{"a"}, "z") {
		t.Error("want false")
	}
	if containsStr(nil, "a") {
		t.Error("nil want false")
	}
}
