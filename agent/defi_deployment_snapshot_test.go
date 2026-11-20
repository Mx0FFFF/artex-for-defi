package agent

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

const snapshotAddress = "0xa1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"

type deFiRoundTrip func(*http.Request) (*http.Response, error)

func (fn deFiRoundTrip) RoundTrip(request *http.Request) (*http.Response, error) { return fn(request) }

func mockDeFiRPC(chainID string, reorg bool, calls *[]string) *http.Client {
	blockReads := 0
	return &http.Client{Transport: deFiRoundTrip(func(request *http.Request) (*http.Response, error) {
		var payload struct {
			ID     int64  `json:"id"`
			Method string `json:"method"`
		}
		body, _ := io.ReadAll(request.Body)
		if err := json.Unmarshal(body, &payload); err != nil {
			return nil, err
		}
		*calls = append(*calls, payload.Method)
		var result any
		switch payload.Method {
		case "eth_chainId":
			result = chainID
		case "eth_getBlockByNumber":
			blockReads++
			hash := "0x" + strings.Repeat("ab", 32)
			if reorg && blockReads > 1 {
				hash = "0x" + strings.Repeat("cd", 32)
			}
			result = map[string]any{"number": "0x64", "hash": hash}
		case "eth_getCode":
			result = "0x6001600055"
		case "eth_getStorageAt":
			result = "0x" + strings.Repeat("0", 24) + strings.Repeat("b2", 20)
		default:
			return nil, fmt.Errorf("unexpected RPC method %q", payload.Method)
		}
		response, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": payload.ID, "result": result})
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(string(response))), Header: make(http.Header)}, nil
	})}
}

func TestDeFiDeploymentSnapshotPinsBlockAndDoesNotLeakRPCURL(t *testing.T) {
	var calls []string
	secret := "https://rpc.example/TOPSECRET?key=TOPSECRET"
	snapshot, err := readDeFiDeploymentSnapshot(t.Context(), secret, mockDeFiRPC("0x1", false, &calls), 1, 100, snapshotAddress)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot["chain_id"] != int64(1) || snapshot["block_number"] != int64(100) {
		t.Fatalf("wrong target context: %+v", snapshot)
	}
	entries := snapshot["addresses"].([]any)
	entry := entries[0].(map[string]any)
	if entry["address"] != snapshotAddress || entry["code_sha256"] != fmt.Sprintf("%x", sha256.Sum256([]byte{0x60, 0x01, 0x60, 0x00, 0x55})) {
		t.Fatalf("wrong code identity: %+v", entry)
	}
	if strings.Contains(fmt.Sprint(snapshot), "TOPSECRET") {
		t.Fatal("RPC credential leaked into snapshot")
	}
	if len(calls) != 7 || calls[0] != "eth_chainId" || calls[len(calls)-1] != "eth_getBlockByNumber" {
		t.Fatalf("unexpected RPC calls: %v", calls)
	}
	path := filepath.Join(t.TempDir(), "deployment.json")
	digest, err := writeDeFiDeploymentSnapshot(path, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := os.ReadFile(path)
	if err != nil || digest != fmt.Sprintf("%x", sha256.Sum256(blob)) {
		t.Fatalf("snapshot artifact hash = %q, %v", digest, err)
	}
}

func TestDeFiDeploymentSnapshotStopsOnChainMismatchAndReorg(t *testing.T) {
	var calls []string
	_, err := readDeFiDeploymentSnapshot(t.Context(), "https://rpc.example/secret", mockDeFiRPC("0xa", false, &calls), 1, 100, snapshotAddress)
	if err == nil || !strings.Contains(err.Error(), "chain ID mismatch") || len(calls) != 1 {
		t.Fatalf("chain mismatch did not stop before code queries: %v, %v", err, calls)
	}
	calls = nil
	_, err = readDeFiDeploymentSnapshot(t.Context(), "https://rpc.example/secret", mockDeFiRPC("0x1", true, &calls), 1, 100, snapshotAddress)
	if err == nil || !strings.Contains(err.Error(), "pinned block changed") {
		t.Fatalf("reorg was accepted: %v", err)
	}
}

func TestDeFiDeploymentSnapshotRedactsTransportErrors(t *testing.T) {
	secret := "https://rpc.example/TOPSECRET?key=TOPSECRET"
	client := &http.Client{Transport: deFiRoundTrip(func(*http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("dial %s failed", secret)
	})}
	_, err := readDeFiDeploymentSnapshot(t.Context(), secret, client, 1, 100, snapshotAddress)
	if err == nil || strings.Contains(err.Error(), "TOPSECRET") {
		t.Fatalf("RPC credential leaked in error: %v", err)
	}
	if _, err := newDeFiRPC("http://rpc.example/plaintext", nil); err == nil {
		t.Fatal("non-HTTPS RPC accepted")
	}
}

func TestDeFiDeploymentSnapshotScopeIsExplicit(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTaskWithOptions("contract", "review", db.TaskCreateOptions{ReviewMode: "defi"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID) //nolint:errcheck
	assets := d.Assets()
	if err := deFiScopedContract(assets, task.ID, 1, snapshotAddress); err == nil {
		t.Fatal("unscoped address accepted")
	}
	if _, err := assets.AddAgentScope(task.ID, "contract", "eip155:1:"+snapshotAddress, "test", "manual"); err != nil {
		t.Fatal(err)
	}
	if err := deFiScopedContract(assets, task.ID, 1, snapshotAddress); err != nil {
		t.Fatal(err)
	}
	if err := deFiScopedContract(assets, task.ID, 10, snapshotAddress); err == nil {
		t.Fatal("same address on a different chain accepted")
	}
}
