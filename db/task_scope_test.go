package db

import (
	"fmt"
	"testing"
	"time"
)

func TestScopeSamplesBoundPlannerContext(t *testing.T) {
	d, _, _ := testSetup(t)
	defer d.Close()
	task, err := d.CreateTask("scope sample", "test", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID) //nolint:errcheck
	companyID, _, err := d.Companies().UpsertCompany(fmt.Sprintf("scope-sample-%d", time.Now().UnixNano()), "")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanupCompany(d, companyID)
	for i := 0; i < 21; i++ {
		if _, err := d.Assets().AddAgentScope(task.ID, "keyword", fmt.Sprintf("sample-%02d", i), "test", "manual"); err != nil {
			t.Fatal(err)
		}
	}
	rows, more, err := d.Assets().ListTaskScopeSample(task.ID, 20)
	if err != nil || len(rows) != 20 || !more {
		t.Fatalf("task scope sample = %d rows, more=%v, err=%v", len(rows), more, err)
	}
	inputs := make([]ScopeInput, 21)
	for i := range inputs {
		inputs[i] = ScopeInput{Kind: "keyword", Value: fmt.Sprintf("company-sample-%02d", i)}
	}
	added, skipped, invalid, errors := d.Companies().AddScopeInputs(companyID, inputs, "test")
	if added != len(inputs) || skipped != 0 || invalid != 0 || len(errors) > 0 {
		t.Fatalf("company scope setup: added=%d skipped=%d invalid=%d errors=%v", added, skipped, invalid, errors)
	}
	companyRows, companyMore, err := d.Companies().GetScopeSample(companyID, 20)
	if err != nil || len(companyRows) != 20 || !companyMore {
		t.Fatalf("company scope sample = %d rows, more=%v, err=%v", len(companyRows), companyMore, err)
	}
}

// TestStripHostPort covers the ip:port / [ipv6]:port stripping used by the
// ip/cidr scope path so a target like "10.0.188.136:3000" no longer 404s.
func TestStripHostPort(t *testing.T) {
	cases := []struct{ in, want string }{
		{"10.0.188.136:3000", "10.0.188.136"},       // the reported IP case
		{"10.0.188.136", "10.0.188.136"},            // bare IPv4 unchanged
		{"[2001:db8::1]:8080", "2001:db8::1"},       // bracketed IPv6 + port
		{"2001:db8::1", "2001:db8::1"},              // bare IPv6 unchanged (has colons)
		{" 1.2.3.4:80 ", "1.2.3.4"},                 // trims surrounding space
		{"example.com:443", "example.com"},          // domain + port → bare host
		{"api.example.com:8080", "api.example.com"}, // subdomain + port
		{"example.com", "example.com"},              // bare domain unchanged
	}
	for _, c := range cases {
		if got := stripHostPort(c.in); got != c.want {
			t.Errorf("stripHostPort(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
