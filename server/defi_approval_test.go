package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
)

func TestDeFiFindingApprovalQueuesHashBoundOperatorDecision(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	task, err := m.CreateTaskWithOptions("DeFi source", "review", db.TaskCreateOptions{ReviewMode: "defi"})
	if err != nil {
		t.Fatal(err)
	}
	defer m.DeleteTask(task.ID, DeleteTaskOptions{}) //nolint:errcheck
	s := &Server{m: m}
	taskID := mustTaskID(t, task.ID)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	ctx = intercept.WithTaskContext(ctx, task.ID, "worker", nil)
	const ref = "DeFi evidence_record: runs/record.json#sha256=abc"
	claim := json.RawMessage(`{"name":"Vault accounting defect","severity":"high","vulnclass":"EVM-09","summary":"Vault accounting defect: missing shares","evidence_record":"runs/record.json","artifact_root":"runs"}`)
	type outcome struct {
		allowed bool
		err     error
	}
	done := make(chan outcome, 1)
	go func() {
		allowed, err := s.approveDeFiFinding(ctx, taskID, ref, claim)
		done <- outcome{allowed, err}
	}()
	var pendingID int64
	var stored string
	for {
		err := m.pg.QueryRow(`SELECT id, tool_input::text FROM intercept_pending
WHERE task_id=$1 AND tool_name='report_finding' AND status='pending' ORDER BY id DESC LIMIT 1`, task.ID).Scan(&pendingID, &stored)
		if err == nil {
			break
		}
		if err != sql.ErrNoRows {
			t.Fatal(err)
		}
		select {
		case <-ctx.Done():
			t.Fatal("DeFi approval was not queued")
		case <-time.After(10 * time.Millisecond):
		}
	}
	if !strings.Contains(stored, ref) || !strings.Contains(stored, "Vault accounting defect") {
		t.Fatalf("approval did not bind claim and evidence hash: %s", stored)
	}
	if err := m.interceptor.Decide(pendingID, true); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-done:
		if got.err != nil || !got.allowed {
			t.Fatalf("approved claim result = %+v", got)
		}
	case <-ctx.Done():
		t.Fatal("approved claim did not resume")
	}
}
