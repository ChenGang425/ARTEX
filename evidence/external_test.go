package evidence

import (
	"bytes"
	"context"
	"database/sql"
	"io"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// 阶段 B — evidence 外部写入路径 (RecordExternal) 的测试。

func TestSplitHTTPMessage(t *testing.T) {
	head, body := splitHTTPMessage([]byte("POST /x HTTP/1.1\r\nHost: a\r\n\r\nbodybytes"))
	if head != "POST /x HTTP/1.1\r\nHost: a" || string(body) != "bodybytes" {
		t.Fatalf("crlf split: head=%q body=%q", head, body)
	}
	head, body = splitHTTPMessage([]byte("GET / HTTP/1.1\nHost: a\n\nlf"))
	if head != "GET / HTTP/1.1\nHost: a" || string(body) != "lf" {
		t.Fatalf("lf split: head=%q body=%q", head, body)
	}
	head, body = splitHTTPMessage([]byte("HEAD-ONLY\r\nNo-Body: 1"))
	if head != "HEAD-ONLY\r\nNo-Body: 1" || body != nil {
		t.Fatalf("no-separator: head=%q body=%v", head, body)
	}
	head, body = splitHTTPMessage(nil)
	if head != "" || body != nil {
		t.Fatalf("empty: head=%q body=%v", head, body)
	}
}

func TestRecordExternal(t *testing.T) {
	s, in, _ := evidenceFixture(t)
	ctx := context.Background()

	reqBody := bytes.Repeat([]byte("ABCD\x00\xff"), 1000)
	respBody := bytes.Repeat([]byte("xyz"), 2000)
	req := append([]byte("POST /login HTTP/1.1\r\nHost: app\r\n\r\n"), reqBody...)
	resp := append([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"), respBody...)

	exchanges := []ExternalExchange{{
		SourceID:    "strix:c-9",
		CapturedAt:  1700000000,
		URL:         "https://app/login",
		Method:      "POST",
		Status:      200,
		ContentType: "text/html",
		Request:     req,
		Response:    resp,
		Role:        "proof",
		Note:        "sqli poc",
	}}

	var hookFinding int64
	r, err := s.RecordExternal(ctx, in, exchanges, func(tx *sql.Tx, f *db.RecordedFinding) error {
		hookFinding = f.FindingID
		return db.MarkStrixFindingSyncedTx(ctx, tx, db.StrixSyncedFinding{TaskID: in.TaskID, ExternalID: "vuln-ext-1", FindingID: f.FindingID})
	})
	if err != nil {
		t.Fatal(err)
	}
	if r.FindingID == 0 || hookFinding != r.FindingID {
		t.Fatalf("after hook finding mismatch: hook=%d finding=%d", hookFinding, r.FindingID)
	}
	if len(r.Traffic.Bindings) != 1 || r.Traffic.Bindings[0].Note != "sqli poc" {
		t.Fatalf("bindings=%+v", r.Traffic.Bindings)
	}

	// Body bytes must round-trip losslessly out of the content-addressed blob store.
	b := r.Traffic.Bindings[0]
	if err := s.WithBinding(ctx, r.FindingID, b.ID, func(bind db.FindingTrafficBinding) error {
		f, _, err := s.OpenBody(bind.Snapshot, "request")
		if err != nil {
			return err
		}
		defer f.Close()
		got, _ := io.ReadAll(f)
		if !bytes.Equal(got, reqBody) {
			t.Fatalf("request body changed: %d vs %d", len(got), len(reqBody))
		}
		f2, _, err := s.OpenBody(bind.Snapshot, "response")
		if err != nil {
			return err
		}
		defer f2.Close()
		got2, _ := io.ReadAll(f2)
		if !bytes.Equal(got2, respBody) {
			t.Fatalf("response body changed: %d vs %d", len(got2), len(respBody))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// The sync mapping committed in the same transaction; re-sync must see it.
	synced, err := s.DB.StrixSyncedExternalIDs(ctx, in.TaskID)
	if err != nil {
		t.Fatal(err)
	}
	if synced["vuln-ext-1"] != r.FindingID {
		t.Fatalf("sync table=%v want %d", synced, r.FindingID)
	}

	// Idempotent re-mark is a no-op (ON CONFLICT DO NOTHING).
	r2, err := s.RecordExternal(ctx, in, exchanges, func(tx *sql.Tx, f *db.RecordedFinding) error {
		return db.MarkStrixFindingSyncedTx(ctx, tx, db.StrixSyncedFinding{TaskID: in.TaskID, ExternalID: "vuln-ext-1", FindingID: f.FindingID})
	})
	if err != nil {
		t.Fatal(err)
	}
	synced2, _ := s.DB.StrixSyncedExternalIDs(ctx, in.TaskID)
	if synced2["vuln-ext-1"] != r.FindingID {
		t.Fatalf("re-sync overwrote mapping: %v (first finding=%d, second=%d)", synced2, r.FindingID, r2.FindingID)
	}
}
