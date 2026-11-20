package agent

import (
	"strings"
	"testing"
)

func TestDeFiPromptRoutingKeepsWebTasksUnchanged(t *testing.T) {
	previous := PromptOverride
	t.Cleanup(func() { PromptOverride = previous })
	PromptOverride = func(key string) (string, bool) { return "USER EDITED " + key, true }

	web := plannerSystem("test login and session handling at example.com", "/data", "/data")
	if strings.Contains(web, "defi-audit") || !strings.Contains(web, "USER EDITED planner") {
		t.Fatalf("web task prompt changed: %q", web)
	}
	defi := plannerSystem("DeFi protocol audit of a Solidity vault", "/data", "/data")
	if !strings.Contains(defi, "USER EDITED planner") || !strings.Contains(defi, `Skill(name="defi-audit")`) {
		t.Fatalf("DeFi planner did not get code-owned skill guidance: %q", defi)
	}
	if got := defiChatPromptTail("pentest", "review this smart contract"); !strings.Contains(got, "defi-audit") {
		t.Fatalf("DeFi pentest guidance missing: %q", got)
	}
	if got := defiChatPromptTail("reporter", "DeFi finding: shares can be inflated"); !strings.Contains(got, "Foundry") {
		t.Fatalf("DeFi reporter guidance missing: %q", got)
	}
	if got := defiChatPromptTail("pentest", "test a web login flow"); got != "" {
		t.Fatalf("web pentest got DeFi guidance: %q", got)
	}
}

func TestDeFiTaskDetectionIsConservative(t *testing.T) {
	for _, text := range []string{
		"DeFi 协议安全审查",
		"audit Solidity ERC-4626 shares",
		"review smart contract",
		"检查预言机价格操纵",
	} {
		if !isDeFiText(text) {
			t.Errorf("missed DeFi task: %q", text)
		}
	}
	for _, text := range []string{
		"test login and session handling",
		"audit the HashiCorp Vault web UI",
		"check an Oracle database server",
	} {
		if isDeFiText(text) {
			t.Errorf("misclassified web task: %q", text)
		}
	}
}
