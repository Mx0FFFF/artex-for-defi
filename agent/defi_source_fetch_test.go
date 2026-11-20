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
)

func mockSourcifyClient(payload map[string]any) *http.Client {
	return &http.Client{Transport: deFiRoundTrip(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet || !strings.Contains(request.URL.String(), "runtimeBytecode.onchainBytecode") {
			return nil, fmt.Errorf("unexpected Sourcify request: %s", request.URL)
		}
		blob, _ := json.Marshal(payload)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(string(blob))), Header: make(http.Header)}, nil
	})}
}

func TestDeFiVerifiedSourceFetchStoresBoundedInertFiles(t *testing.T) {
	code := []byte{0x60, 0x01, 0x60, 0x00, 0x55}
	payload := map[string]any{
		"chainId": "1", "address": snapshotAddress, "match": "exact_match",
		"runtimeMatch":    "exact_match",
		"runtimeBytecode": map[string]any{"onchainBytecode": "0x" + fmt.Sprintf("%x", code)},
		"sources":         map[string]any{"contracts/Vault.sol": map[string]any{"content": "contract Vault {}\n"}},
	}
	responsePath, digest, err := fetchDeFiVerifiedSource(t.Context(), 1, snapshotAddress, t.TempDir(), mockSourcifyClient(payload))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(responsePath)
	if err != nil || digest != fmt.Sprintf("%x", sha256.Sum256(raw)) {
		t.Fatalf("response digest = %q, %v", digest, err)
	}
	source, err := os.ReadFile(filepath.Join(filepath.Dir(responsePath), "sources", "contracts", "Vault.sol"))
	if err != nil || string(source) != "contract Vault {}\n" {
		t.Fatalf("verified source = %q, %v", source, err)
	}
	manifest, err := os.ReadFile(filepath.Join(filepath.Dir(responsePath), "manifest.json"))
	if err != nil || !strings.Contains(string(manifest), fmt.Sprintf("%x", sha256.Sum256(code))) {
		t.Fatalf("source manifest lacks runtime hash: %s, %v", manifest, err)
	}
}

func TestDeFiVerifiedSourceFetchRejectsTraversal(t *testing.T) {
	output := t.TempDir()
	payload := map[string]any{
		"chainId": "1", "address": snapshotAddress,
		"runtimeBytecode": map[string]any{"onchainBytecode": "0x6001"},
		"sources":         map[string]any{"../outside.sol": map[string]any{"content": "secret"}},
	}
	_, _, err := fetchDeFiVerifiedSource(t.Context(), 1, snapshotAddress, output, mockSourcifyClient(payload))
	if err == nil || !strings.Contains(err.Error(), "unsafe verified source path") {
		t.Fatalf("traversal source accepted: %v", err)
	}
	entries, err := os.ReadDir(output)
	if err != nil || len(entries) != 0 {
		t.Fatalf("untrusted source wrote files before validation: %+v, %v", entries, err)
	}
}
