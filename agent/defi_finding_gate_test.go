package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
)

func TestDeFiFindingValidatorUsesSandbox(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("DeFi analyzer sandbox requires Linux")
	}
	data := t.TempDir()
	taskRoot := filepath.Join(data, "tasks", "1")
	workerDir := filepath.Join(taskRoot, "i2")
	if err := os.MkdirAll(workerDir, 0o700); err != nil {
		t.Fatal(err)
	}
	record := filepath.Join(taskRoot, "record.json")
	if err := os.WriteFile(record, []byte(`{"status":"confirmed","severity":"high","title":"Synthetic defect","detector_ids":["EVM-01"],"impact":{"description":"Synthetic loss"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	scripts := filepath.Join(t.TempDir(), "defi-audit", "scripts")
	if err := os.MkdirAll(scripts, 0o700); err != nil {
		t.Fatal(err)
	}
	sandbox, err := os.ReadFile(filepath.Join("..", "skills", "defi-audit", "scripts", "sandbox_exec.py"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scripts, "sandbox_exec.py"), sandbox, 0o600); err != nil {
		t.Fatal(err)
	}
	validator := filepath.Join(scripts, "evidence.py")
	stub := `import json, sys
from pathlib import Path
outside = Path(sys.argv[2]).parent.parent.parent / "outside.txt"
try:
    outside.write_text("escaped")
except OSError:
    pass
print(json.dumps({"ok": True}))
`
	if err := os.WriteFile(validator, []byte(stub), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := DeFiEvidenceScriptPath
	DeFiEvidenceScriptPath = func() string { return validator }
	t.Cleanup(func() { DeFiEvidenceScriptPath = previous })
	ctx := intercept.WithReviewContext(t.Context(), workerDir, intercept.ReviewBackground{})
	ref, err := validateDeFiFindingRecord(ctx, 1, record, taskRoot, "high", "EVM-01", "Synthetic defect", "Synthetic defect: Synthetic loss")
	if err != nil || !strings.Contains(ref, "sha256=") {
		t.Fatalf("sandboxed validation = %q, %v", ref, err)
	}
	if _, err := os.Stat(filepath.Join(data, "outside.txt")); !os.IsNotExist(err) {
		t.Fatalf("validator escaped task root: %v", err)
	}
}

func TestDeFiFindingScopeRequiresExactDeploymentBinding(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTaskWithOptions("onchain", "review", db.TaskCreateOptions{ReviewMode: "defi"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID) //nolint:errcheck
	root := filepath.Join(t.TempDir(), "tasks", strconv.FormatInt(task.ID, 10))
	worker := filepath.Join(root, "i1")
	if err := os.MkdirAll(worker, 0o700); err != nil {
		t.Fatal(err)
	}
	record := filepath.Join(root, "record.json")
	binding := filepath.Join(root, "deployment_binding.json")
	ctx := intercept.WithReviewContext(t.Context(), worker, intercept.ReviewBackground{})
	if err := os.WriteFile(record, []byte(`{"environment":{"chain":"1","source_bytecode_match":"unverified"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateDeFiFindingScope(ctx, d.Assets(), task.ID, record, root); err == nil || !strings.Contains(err.Error(), "缺少已验证") {
		t.Fatalf("unverified deployment claim accepted: %v", err)
	}
	if err := os.WriteFile(record, []byte(`{"environment":{"chain":"1","source_bytecode_match":"verified"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binding, []byte(`{"chain_id":1,"address":"0xa1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateDeFiFindingScope(ctx, d.Assets(), task.ID, record, root); err == nil || !strings.Contains(err.Error(), "范围") {
		t.Fatalf("unscoped deployment claim accepted: %v", err)
	}
	if _, err := d.Assets().AddAgentScope(task.ID, "contract", "eip155:1:0xa1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1", "test", "manual"); err != nil {
		t.Fatal(err)
	}
	if err := validateDeFiFindingScope(ctx, d.Assets(), task.ID, record, root); err != nil {
		t.Fatal(err)
	}
}

func TestDeFiFindingApprovalFailsClosed(t *testing.T) {
	ctx := t.Context()
	input := json.RawMessage(`{"name":"example"}`)
	if err := requireDeFiFindingApproval(ctx, 1, "record#sha256=abc", input, nil); err == nil {
		t.Fatal("missing approver accepted")
	}
	denied := func(context.Context, int64, string, json.RawMessage) (bool, error) { return false, nil }
	if err := requireDeFiFindingApproval(ctx, 1, "record#sha256=abc", input, denied); err == nil {
		t.Fatal("denied claim accepted")
	}
	approved := func(_ context.Context, taskID int64, ref string, raw json.RawMessage) (bool, error) {
		if taskID != 1 || ref != "record#sha256=abc" || string(raw) != string(input) {
			t.Fatalf("approval reviewed wrong claim: %d %s %s", taskID, ref, raw)
		}
		return true, nil
	}
	if err := requireDeFiFindingApproval(ctx, 1, "record#sha256=abc", input, approved); err != nil {
		t.Fatal(err)
	}
}

func TestReportFindingMissingTaskIDFailsClosed(t *testing.T) {
	toolset := NewToolSet(new(db.ExplorationStore), "worker")
	result, err := toolset.addFinding().Call(t.Context(), json.RawMessage(`{"vulnclass":"EVM-01","severity":"high","summary":"candidate"}`), nil)
	if err != nil || !strings.Contains(result.Flatten(), "任务 ID") {
		t.Fatalf("finding without task ID was accepted: %v %s", err, result.Flatten())
	}
}

func TestDeFiFindingRequiresStructuredEvidenceBeforeAnyRecorderPath(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTaskWithOptions("DeFi uploaded source", "find defects", db.TaskCreateOptions{ReviewMode: "defi"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID) //nolint:errcheck
	unbound := NewToolSet(d.Exploration(task.ExplorationID), "worker")
	unboundResult, err := unbound.addFinding().Call(t.Context(), json.RawMessage(`{"vulnclass":"EVM-01","severity":"high","summary":"synthetic candidate"}`), nil)
	if err != nil || !strings.Contains(unboundResult.Flatten(), "任务 ID") {
		t.Fatalf("finding without task ID was accepted: %v %s", err, unboundResult.Flatten())
	}
	toolset := NewToolSet(d.Exploration(task.ExplorationID), "worker")
	toolset.SetTaskID(task.ID)
	// Deliberately leave FindingRecorder nil: the old direct DB fallback must
	// not bypass the DeFi evidence gate.
	res, err := toolset.addFinding().Call(t.Context(), json.RawMessage(`{"vulnclass":"EVM-01","severity":"high","summary":"synthetic candidate"}`), nil)
	if err != nil || !strings.Contains(res.Flatten(), "evidence_record") {
		t.Fatalf("missing evidence accepted: %v %s", err, res.Flatten())
	}
	var count int
	if err := d.QueryRow(`SELECT count(*) FROM findings WHERE task_id=$1`, task.ID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("finding persisted despite failed gate: count=%d err=%v", count, err)
	}
}

func TestDeFiFindingRejectsLaunderedReportFields(t *testing.T) {
	root := filepath.Join(t.TempDir(), "tasks", "1")
	workerDir := filepath.Join(root, "i2")
	if err := os.MkdirAll(workerDir, 0o700); err != nil {
		t.Fatal(err)
	}
	record := filepath.Join(root, "record.json")
	if err := os.WriteFile(record, []byte(`{"status":"confirmed","severity":"high","title":"Synthetic authorization defect","detector_ids":["EVM-01"],"impact":{"description":"Ten synthetic units moved"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := intercept.WithReviewContext(t.Context(), workerDir, intercept.ReviewBackground{})
	checks := []struct {
		class, name, summary, want string
	}{
		{"ECO-01", "Synthetic authorization defect", "Synthetic authorization defect: Ten synthetic units moved", "vulnclass"},
		{"EVM-01", "Different claim", "Synthetic authorization defect: Ten synthetic units moved", "name"},
		{"EVM-01", "Synthetic authorization defect", "Different impact", "summary"},
	}
	for _, check := range checks {
		_, err := validateDeFiFindingRecord(ctx, 1, record, root, "high", check.class, check.name, check.summary)
		if err == nil || !strings.Contains(err.Error(), check.want) {
			t.Errorf("laundered claim not rejected (%s): %v", check.want, err)
		}
	}
}
