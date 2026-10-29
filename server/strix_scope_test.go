package server

import (
	"reflect"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// 阶段 C — task_scope → strix scope 目标映射 (task 6.1) 的纯函数测试,不依赖 PG。

func TestTaskScopeTargets(t *testing.T) {
	rows := []db.TaskScope{
		{Kind: "root_domain", Domain: "Example.com"},
		{Kind: "subdomain", Domain: "api.example.com"},
		{Kind: "ip", Net: "10.0.0.5/32"},
		{Kind: "cidr", Net: "10.0.1.0/24"},
		{Kind: "company", CompanyName: "Acme"}, // no host boundary → skipped
		{Kind: "icp", Value: "京ICP备1号"},         // skipped
		{Kind: "keyword", Value: "acme"},        // skipped
		{Kind: "root_domain", Domain: "example.com"}, // dup after lowercasing
	}
	got := taskScopeTargets(rows)
	want := []string{"example.com", "api.example.com", "10.0.0.5/32", "10.0.1.0/24"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("taskScopeTargets=%v want %v", got, want)
	}
}

func TestTaskScopeTargetsEmpty(t *testing.T) {
	if got := taskScopeTargets(nil); len(got) != 0 {
		t.Errorf("want empty, got %v", got)
	}
	// Only non-host kinds → empty.
	rows := []db.TaskScope{{Kind: "company"}, {Kind: "icp", Value: "x"}}
	if got := taskScopeTargets(rows); len(got) != 0 {
		t.Errorf("want empty, got %v", got)
	}
}

func TestMergeScopeTargets(t *testing.T) {
	got := mergeScopeTargets(
		[]string{"example.com", "10.0.0.5/32"},
		[]string{"API.example.com", "example.com", "", "  ", "app.example.com"},
	)
	want := []string{"example.com", "10.0.0.5/32", "api.example.com", "app.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("mergeScopeTargets=%v want %v", got, want)
	}
}

func TestMergeScopeTargetsEmpty(t *testing.T) {
	if got := mergeScopeTargets(nil, nil); len(got) != 0 {
		t.Errorf("want empty, got %v", got)
	}
}
