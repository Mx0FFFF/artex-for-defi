package db

import (
	"fmt"
	"strings"
	"testing"
)

func TestDefiAssetIdentityNormalization(t *testing.T) {
	address := "0xAAbbCCddEEff0011223344556677889900AAbbCC"
	key, err := ContractScopeKey(1, address)
	if err != nil {
		t.Fatal(err)
	}
	if key != "eip155:1:"+strings.ToLower(address) {
		t.Fatalf("unexpected contract key: %q", key)
	}
	chainID, gotAddress, gotKey, err := ParseContractScope("EIP155:1:" + address)
	if err != nil || chainID != 1 || gotAddress != strings.ToLower(address) || gotKey != key {
		t.Fatalf("scope parse: chain=%d address=%q key=%q err=%v", chainID, gotAddress, gotKey, err)
	}
	for _, bad := range []string{"", "eip155:0:" + address, "eip155:1:0x123", "eip155:1:0xGGbbCCddEEff0011223344556677889900AAbbCC"} {
		if _, _, _, err := ParseContractScope(bad); err == nil {
			t.Errorf("accepted invalid contract scope %q", bad)
		}
	}
	url, err := NormalizeRepositoryURL("HTTPS://GitHub.com/Org/Protocol.git/")
	if err != nil || url != "https://github.com/Org/Protocol" {
		t.Fatalf("repository normalization: %q, %v", url, err)
	}
	pinned, err := RepositoryScopeKey(url, "abc123")
	if err != nil || pinned != url+"#abc123" {
		t.Fatalf("pinned repository scope: %q, %v", pinned, err)
	}
	if got, err := NormalizeRepositoryScope("HTTPS://GitHub.com/Org/Protocol.git/#abc123"); err != nil || got != pinned {
		t.Fatalf("normalized pinned scope: %q, %v", got, err)
	}
	if _, err := NormalizeRepositoryScope(url + "#"); err == nil {
		t.Error("accepted empty pinned revision")
	}
	for _, bad := range []string{"http://github.com/org/repo", "https://user:pass@github.com/org/repo", "https://github.com/org/repo?token=x", "https://github.com/"} {
		if _, err := NormalizeRepositoryURL(bad); err == nil {
			t.Errorf("accepted invalid repository URL %q", bad)
		}
	}
}

func TestDefiAssetInterceptIdentity(t *testing.T) {
	contract := &Asset{ID: 7, Type: "contract", Address: "0x0000000000000000000000000000000000000007"}
	if !strings.Contains(contract.InterceptLabel(), contract.Address) {
		t.Fatalf("contract intercept label omits address: %q", contract.InterceptLabel())
	}
	repository := &Asset{ID: 8, Type: "repository", RepositoryURL: "https://github.com/org/repo"}
	domains, _, urls := repository.interceptCandidates()
	if len(domains) == 0 || domains[0] != "github.com" || len(urls) == 0 || urls[0] != repository.RepositoryURL {
		t.Fatalf("repository intercept candidates: domains=%v urls=%v", domains, urls)
	}
}

func TestDefiAssetsAreScopedAndLinked(t *testing.T) {
	d, as, _ := testSetup(t)
	defer d.Close()
	task, err := d.CreateTask("DeFi asset test", "review contract and source", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID) //nolint:errcheck
	address := fmt.Sprintf("0x%040x", task.ID)
	repoURL := fmt.Sprintf("https://example.com/defi/protocol-%d", task.ID)
	repoID, err := as.UpsertRepository(UpsertRepositoryReq{
		RepositoryURL: repoURL + ".git", Revision: "abc123", ProtocolName: "Test Protocol", TaskID: task.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer deleteAsset(d, repoID)
	contractID, err := as.UpsertContract(UpsertContractReq{
		ChainID: 1, Address: strings.ToUpper(address[:2]) + address[2:],
		ContractName: "Vault", ProtocolName: "Test Protocol", RepositoryURL: repoURL, TaskID: task.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer deleteAsset(d, contractID)
	contractID2, err := as.UpsertContract(UpsertContractReq{ChainID: 1, Address: address, TaskID: task.ID})
	if err != nil || contractID2 != contractID {
		t.Fatalf("contract dedup: %d vs %d, err=%v", contractID, contractID2, err)
	}
	repoID2, err := as.UpsertRepository(UpsertRepositoryReq{RepositoryURL: repoURL, Revision: "abc123", TaskID: task.ID})
	if err != nil || repoID2 != repoID {
		t.Fatalf("repository dedup: %d vs %d, err=%v", repoID, repoID2, err)
	}
	otherRevisionID, err := as.UpsertRepository(UpsertRepositoryReq{RepositoryURL: repoURL, Revision: "def456"})
	if err != nil || otherRevisionID == repoID {
		t.Fatalf("repository revision identity: new=%d existing=%d err=%v", otherRevisionID, repoID, err)
	}
	defer deleteAsset(d, otherRevisionID)
	assets, err := as.QueryByTask(task.ID, "", 10, 0)
	if err != nil || len(assets) != 2 {
		t.Fatalf("task assets: len=%d err=%v", len(assets), err)
	}
	scopes, err := as.ListTaskScope(task.ID)
	if err != nil || len(scopes) != 2 {
		t.Fatalf("task scopes: len=%d err=%v", len(scopes), err)
	}
	for _, scope := range scopes {
		if scope.Kind == "repository" && scope.Value != repoURL+"#abc123" {
			t.Fatalf("repository scope not revision-pinned: %+v", scope)
		}
	}
	contracts, err := as.QueryDSLInScope("chain_id==1", "contract", task.ID, 10, 0)
	if err != nil || len(contracts) != 1 || contracts[0].ID != contractID {
		t.Fatalf("scoped contract query: %+v, %v", contracts, err)
	}
	repositories, err := as.QueryDSLInScope("repository_url=="+repoURL, "repository", task.ID, 10, 0)
	if err != nil || len(repositories) != 1 || repositories[0].ID != repoID {
		t.Fatalf("revision-pinned repository query: %+v, %v", repositories, err)
	}
	cov, err := as.TaskCoverage(task.ID, task.ExplorationID)
	if err != nil || cov.Denominator != 2 {
		t.Fatalf("coverage: %+v, %v", cov, err)
	}
	graph, err := as.BuildCoverageGraph(task.ID, task.ExplorationID)
	if err != nil {
		t.Fatal(err)
	}
	linked := false
	for _, edge := range graph.Edges {
		if edge.Src == assetKey(contractID) && edge.Dst == assetKey(repoID) {
			linked = true
		}
	}
	if !linked {
		t.Fatalf("contract → repository edge missing: %+v", graph.Edges)
	}
}
