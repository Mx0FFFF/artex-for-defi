package server

import (
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

func TestRepositoryScopeDoesNotTurnCustomTriggersIntoDeFi(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	task, err := m.CreateTaskWithOptions("repository in red-team task", "review", db.TaskCreateOptions{ReviewMode: "custom"})
	if err != nil {
		t.Fatal(err)
	}
	defer m.DeleteTask(task.ID, DeleteTaskOptions{}) //nolint:errcheck
	if _, err := m.Assets().AddAgentScope(mustTaskID(t, task.ID), "repository", "https://github.com/example/protocol", "test", "manual"); err != nil {
		t.Fatal(err)
	}
	if (&Server{m: m}).triggeredDeFiTask(mustTaskID(t, task.ID)) {
		t.Fatal("custom task trigger was treated as a DeFi task")
	}
}

func TestDeFiTriggeredReporterCannotUpdateAnotherTask(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	taskOne, err := m.CreateTaskWithOptions("first", "review", db.TaskCreateOptions{ReviewMode: "defi"})
	if err != nil {
		t.Fatal(err)
	}
	taskTwo, err := m.CreateTaskWithOptions("second", "review", db.TaskCreateOptions{ReviewMode: "defi"})
	if err != nil {
		t.Fatal(err)
	}
	defer m.DeleteTask(taskOne.ID, DeleteTaskOptions{}) //nolint:errcheck
	defer m.DeleteTask(taskTwo.ID, DeleteTaskOptions{}) //nolint:errcheck
	recorded, err := taskTwo.Store.RecordFinding(t.Context(), db.RecordFindingInput{
		TaskID: mustTaskID(t, taskTwo.ID), VulnClass: "test", Name: "synthetic",
		Severity: "low", Summary: "synthetic", Evidence: "fixture", Worker: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{m: m}
	input := map[string]any{"finding_id": recorded.NodeID, "report": "synthetic report"}
	firstCtx := agent.WithDeFiTriggeredTask(t.Context(), mustTaskID(t, taskOne.ID))
	workflowCall(t, firstCtx, s.toolUpdateFindingReport(), input, true)
	secondCtx := agent.WithDeFiTriggeredTask(t.Context(), mustTaskID(t, taskTwo.ID))
	workflowCall(t, secondCtx, s.toolUpdateFindingReport(), input, false)
}
