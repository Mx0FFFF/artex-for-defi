package db

import "testing"

func TestConversationSourceTaskPersistsForFollowUpsAndRetests(t *testing.T) {
	d, _, _ := testSetup(t)
	defer d.Close()
	task, err := d.CreateTask("DeFi task", "review", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID) //nolint:errcheck
	c, err := d.CreateConversation("reporter", "trigger", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteConversation(c.ID) //nolint:errcheck
	if source, err := d.ConversationSourceTask(c.ID); err != nil || source != 0 {
		t.Fatalf("manual conversation source = %d, %v", source, err)
	}
	if err := d.SetConversationSourceTask(c.ID, task.ID); err != nil {
		t.Fatal(err)
	}
	if source, err := d.ConversationSourceTask(c.ID); err != nil || source != task.ID {
		t.Fatalf("triggered conversation source = %d, %v", source, err)
	}
	findingID, err := d.AddFinding(task.ID, 0, "test", "source link", "high", "summary", "evidence", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteFinding(findingID) //nolint:errcheck
	_, retestConversation, created, err := d.CreateFindingRetest(t.Context(), findingID, "")
	if err != nil || !created || retestConversation == nil {
		t.Fatalf("retest conversation = %+v, created=%v, err=%v", retestConversation, created, err)
	}
	defer d.DeleteConversation(retestConversation.ID) //nolint:errcheck
	if source, err := d.ConversationSourceTask(retestConversation.ID); err != nil || source != task.ID {
		t.Fatalf("retest conversation source = %d, %v", source, err)
	}
}
