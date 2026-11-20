package db

import "testing"

func TestTaskReviewModePersistsAndDefaults(t *testing.T) {
	d, _, _ := testSetup(t)
	defer d.Close()
	defi, err := d.CreateTaskWithOptions("defi mode", "review uploaded source", TaskCreateOptions{ReviewMode: "defi"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(defi.ID) //nolint:errcheck
	mode, err := d.TaskReviewMode(defi.ID)
	if err != nil || mode != "defi" {
		t.Fatalf("persisted mode = %q, %v", mode, err)
	}
	reloaded, err := d.GetTask(defi.ID)
	if err != nil || reloaded == nil || reloaded.ReviewMode != "defi" {
		t.Fatalf("reloaded task mode: %+v, %v", reloaded, err)
	}
	custom, err := d.CreateTaskWithOptions("legacy mode", "review web", TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(custom.ID) //nolint:errcheck
	if custom.ReviewMode != "custom" {
		t.Fatalf("legacy task mode = %q", custom.ReviewMode)
	}
	if _, err := d.CreateTaskWithOptions("bad mode", "goal", TaskCreateOptions{ReviewMode: "unknown"}); err == nil {
		t.Fatal("invalid review mode accepted")
	}
}
