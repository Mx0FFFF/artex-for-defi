package agent

import (
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestExplicitDeFiTaskUsesPersistedMode(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	defi, err := d.CreateTaskWithOptions("uploaded source", "review", db.TaskCreateOptions{ReviewMode: "defi"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(defi.ID) //nolint:errcheck
	if !explicitDeFiTask(d.Exploration(defi.ExplorationID)) {
		t.Fatal("explicit DeFi mode was not detected")
	}
	custom, err := d.CreateTask("web target", "review", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(custom.ID) //nolint:errcheck
	if explicitDeFiTask(d.Exploration(custom.ExplorationID)) {
		t.Fatal("custom task was treated as DeFi")
	}
	if _, err := d.Assets().AddAgentScope(custom.ID, "repository", "https://github.com/example/protocol", "test", "manual"); err != nil {
		t.Fatal(err)
	}
	if explicitDeFiTask(d.Exploration(custom.ExplorationID)) {
		t.Fatal("custom task with repository scope was treated as DeFi")
	}
}
