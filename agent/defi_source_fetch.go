package agent

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/google/uuid"
)

const (
	deFiSourcifyResponseLimit = 20 << 20
	deFiSourcifySourceLimit   = 5 << 20
)

func safeDeFiSourceName(raw string) (string, error) {
	if raw == "" || len(raw) > 1024 || strings.ContainsAny(raw, "\\\x00:") || strings.HasPrefix(raw, "/") {
		return "", errors.New("unsafe verified source path")
	}
	for _, part := range strings.Split(raw, "/") {
		if part == "" || part == "." || part == ".." {
			return "", errors.New("unsafe verified source path")
		}
	}
	return filepath.FromSlash(raw), nil
}

// fetchDeFiVerifiedSource fetches exactly one scoped contract over HTTPS. It
// saves source files as inert data and never executes them or follows proxies.
func fetchDeFiVerifiedSource(ctx context.Context, chainID int64, address, outDir string, client *http.Client) (string, string, error) {
	key, err := db.ContractScopeKey(chainID, address)
	if err != nil {
		return "", "", err
	}
	address = strings.TrimPrefix(key, fmt.Sprintf("eip155:%d:", chainID))
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}}
	}
	endpoint := fmt.Sprintf("https://sourcify.dev/server/v2/contract/%d/%s?fields=sources,compilation,proxyResolution,runtimeBytecode.onchainBytecode", chainID, address)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", "", errors.New("Sourcify request could not be prepared")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "ARTEX-defi-audit/1.0")
	response, err := client.Do(request)
	if err != nil {
		return "", "", errors.New("Sourcify lookup failed or timed out")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("Sourcify HTTP error %d", response.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, deFiSourcifyResponseLimit+1))
	if err != nil || len(raw) > deFiSourcifyResponseLimit {
		return "", "", errors.New("Sourcify response exceeded the byte limit or could not be read")
	}
	var data struct {
		ChainID         json.RawMessage                       `json:"chainId"`
		Address         string                                `json:"address"`
		Match           string                                `json:"match"`
		RuntimeMatch    string                                `json:"runtimeMatch"`
		ProxyResolution json.RawMessage                       `json:"proxyResolution"`
		Sources         map[string]map[string]json.RawMessage `json:"sources"`
		RuntimeBytecode struct {
			OnchainBytecode string `json:"onchainBytecode"`
		} `json:"runtimeBytecode"`
	}
	if json.Unmarshal(raw, &data) != nil {
		return "", "", errors.New("Sourcify returned invalid JSON")
	}
	var responseChainString string
	var responseChainNumber int64
	chainMatches := json.Unmarshal(data.ChainID, &responseChainString) == nil && responseChainString == fmt.Sprint(chainID)
	if !chainMatches {
		chainMatches = json.Unmarshal(data.ChainID, &responseChainNumber) == nil && responseChainNumber == chainID
	}
	if !chainMatches || !strings.EqualFold(data.Address, address) {
		return "", "", errors.New("Sourcify response does not match the scoped contract")
	}
	if len(data.Sources) == 0 || len(data.Sources) > 1000 {
		return "", "", errors.New("Sourcify response lacks a bounded source set")
	}
	codeBytes, codeHash, err := deFiCodeSummary(data.RuntimeBytecode.OnchainBytecode)
	if err != nil {
		return "", "", errors.New("Sourcify response lacks bounded runtime bytecode")
	}
	files := make(map[string][]byte, len(data.Sources))
	for name, source := range data.Sources {
		path, err := safeDeFiSourceName(name)
		if err != nil {
			return "", "", err
		}
		contentRaw, ok := source["content"]
		if !ok {
			return "", "", errors.New("Sourcify source content is missing")
		}
		var sourceText string
		if json.Unmarshal(contentRaw, &sourceText) != nil {
			return "", "", errors.New("Sourcify source content is not text")
		}
		content := []byte(sourceText)
		if len(content) > deFiSourcifySourceLimit {
			return "", "", errors.New("Sourcify source file exceeds size limit")
		}
		files[path] = content
	}
	root := filepath.Join(outDir, "verified-"+uuid.NewString())
	if err := os.Mkdir(root, 0o700); err != nil {
		return "", "", err
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.RemoveAll(root)
		}
	}()
	responsePath := filepath.Join(root, "sourcify-response.json")
	if err := os.WriteFile(responsePath, raw, 0o600); err != nil {
		return "", "", err
	}
	sourceHashes := map[string]string{}
	for name, content := range files {
		path := filepath.Join(root, "sources", name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return "", "", err
		}
		if err := os.WriteFile(path, content, 0o600); err != nil {
			return "", "", err
		}
		sourceHashes[filepath.ToSlash(name)] = fmt.Sprintf("%x", sha256.Sum256(content))
	}
	responseHash := fmt.Sprintf("%x", sha256.Sum256(raw))
	manifest := map[string]any{
		"chain_id": chainID, "address": address, "match": data.Match,
		"runtime_match": data.RuntimeMatch, "runtime_code_bytes": codeBytes,
		"runtime_code_sha256": codeHash, "source_count": len(files),
		"source_sha256": sourceHashes, "response_sha256": responseHash,
		"proxy_resolution": data.ProxyResolution,
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return "", "", err
	}
	if err := os.WriteFile(filepath.Join(root, "manifest.json"), append(manifestBytes, '\n'), 0o600); err != nil {
		return "", "", err
	}
	complete = true
	return responsePath, responseHash, nil
}
