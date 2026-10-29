package db

import (
	"context"
	"database/sql"
	"errors"
)

// StrixSyncedFinding records that a strix finding (identified by its stable
// external id, e.g. "vuln-0001") was already reflected into ARTEX as finding
// findingID for taskID. It is the idempotency anchor for阶段 B's periodic
// evidence sync: a strix finding that keeps reappearing in export_findings is
// only written into ARTEX once (design D6 / Open Question — external-id
// idempotency on the sync side, ARTEX finding-cases merge stays authoritative).
type StrixSyncedFinding struct {
	TaskID     int64
	ExternalID string
	FindingID  int64
}

// StrixSyncedExternalIDs returns the set of strix external ids already synced
// for a task, so the caller can skip re-mapping them. A zero task or nil DB
// yields an empty set (feature-off / chat runs never sync).
func (d *DB) StrixSyncedExternalIDs(ctx context.Context, taskID int64) (map[string]int64, error) {
	out := map[string]int64{}
	if d == nil || taskID == 0 {
		return out, nil
	}
	rows, err := d.QueryContext(ctx, `SELECT external_id, finding_id FROM strix_finding_sync WHERE task_id=$1`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var ext string
		var fid int64
		if err := rows.Scan(&ext, &fid); err != nil {
			return nil, err
		}
		out[ext] = fid
	}
	return out, rows.Err()
}

// MarkStrixFindingSyncedTx records the strix→ARTEX finding mapping inside the
// caller's transaction (so "finding written" and "sync recorded" commit atomically
// with the evidence write). ON CONFLICT keeps the first mapping — a re-sync of the
// same external id is a no-op even if it raced a concurrent writer.
func MarkStrixFindingSyncedTx(ctx context.Context, tx *sql.Tx, rec StrixSyncedFinding) error {
	if rec.TaskID == 0 || rec.ExternalID == "" || rec.FindingID == 0 {
		return errors.New("strix 同步映射缺少 task_id/external_id/finding_id")
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO strix_finding_sync(task_id,external_id,finding_id)
VALUES($1,$2,$3) ON CONFLICT(task_id,external_id) DO NOTHING`, rec.TaskID, rec.ExternalID, rec.FindingID)
	return err
}
