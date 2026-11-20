package agent

import (
	"context"
	"iter"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/llm"
)

type deFiToolCaptureProvider struct{ names []string }

func (p *deFiToolCaptureProvider) Stream(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(func(llm.StreamEvent, error) bool) {}
}

func TestDeFiWorkerKeepsNormalTools(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTaskWithOptions("vault source", "review", db.TaskCreateOptions{ReviewMode: "defi"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID) //nolint:errcheck
	ts := d.Exploration(task.ExplorationID)
	id, err := ts.AddNode("intent", map[string]any{"summary": "inspect vault"}, 0, "running", "planner", nil)
	if err != nil {
		t.Fatal(err)
	}
	provider := &deFiToolCaptureProvider{}
	worker := NewWorker(provider, "fixture", t.TempDir(), nil, 0, 1)
	worker.SetDeFiSkillDir(filepath.Join("..", "skills"))
	worker.SetNonStreaming(func() bool { return true })
	if _, _, err := worker.Execute(t.Context(), "worker", task.ID, d.Assets(), ts, &db.Node{ID: id}, nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, name := range provider.names {
		seen[name] = true
	}
	for _, name := range []string{"Bash", "Read", "Write", "Edit", "defi_analysis"} {
		if !seen[name] {
			t.Fatalf("DeFi worker lost %s: %v", name, provider.names)
		}
	}
}

func (p *deFiToolCaptureProvider) Complete(_ context.Context, request llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	for _, tool := range request.Tools {
		p.names = append(p.names, tool.Name)
	}
	return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("done")}}, "end_turn", llm.Usage{}, nil
}

func TestDeFiTriggeredChatKeepsNormalToolsAndTaskContext(t *testing.T) {
	data := t.TempDir()
	if err := os.MkdirAll(filepath.Join(data, "tasks", "1"), 0o700); err != nil {
		t.Fatal(err)
	}
	provider := &deFiToolCaptureProvider{}
	chat := NewChatAgent(provider, "fixture", data, nil, 10000)
	chat.SetNonStreaming(func() bool { return true })
	ctx := WithDeFiTriggeredTask(t.Context(), 1)
	if _, err := chat.Chat(ctx, "reporter", "conv-1", "review finding", 1, time.Minute, true, nil); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, name := range provider.names {
		seen[name] = true
	}
	if !seen["Bash"] || !seen["Read"] || !seen["Write"] || !seen["Edit"] {
		t.Fatalf("triggered DeFi chat lost normal tools: %v", provider.names)
	}
	if _, err := os.Stat(filepath.Join(data, "tasks", "1", "triggered", "conv-1")); err != nil {
		t.Fatal(err)
	}
}
