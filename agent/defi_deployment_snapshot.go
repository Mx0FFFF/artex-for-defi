package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
)

const (
	deFiRPCResponseLimit = 2 << 20
	deFiCodeBytesLimit   = 256 << 10
	deFiSlotSpecURL      = "https://eips.ethereum.org/EIPS/eip-1967"
)

var deFiProxySlots = []struct{ name, key string }{
	{"implementation", "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"},
	{"admin", "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"},
	{"beacon", "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"},
}

type deFiRPC struct {
	url     string
	client  *http.Client
	nextID  int64
	methods map[string]bool
}

func newDeFiRPC(raw string, client *http.Client) (*deFiRPC, error) {
	u, err := url.Parse(raw)
	if err != nil || u == nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return nil, errors.New("RPC_URL must be an HTTPS URL without embedded credentials or fragment")
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}}
	}
	return &deFiRPC{url: raw, client: client, methods: map[string]bool{}}, nil
}

func (r *deFiRPC) call(ctx context.Context, method string, params []any, result any) error {
	switch method {
	case "eth_chainId", "eth_getBlockByNumber", "eth_getCode", "eth_getStorageAt":
	default:
		return errors.New("RPC method is not on the read-only allowlist")
	}
	r.nextID++
	requestBody, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": r.nextID, "method": method, "params": params})
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, r.url, bytes.NewReader(requestBody))
	if err != nil {
		return errors.New("RPC request could not be prepared")
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := r.client.Do(request)
	if err != nil {
		return errors.New("RPC transport failed or timed out")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("RPC HTTP error %d", response.StatusCode)
	}
	content, err := io.ReadAll(io.LimitReader(response.Body, deFiRPCResponseLimit+1))
	if err != nil || len(content) > deFiRPCResponseLimit {
		return errors.New("RPC response exceeded the byte limit or could not be read")
	}
	var envelope struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      int64           `json:"id"`
		Result  json.RawMessage `json:"result"`
		Error   json.RawMessage `json:"error"`
	}
	if json.Unmarshal(content, &envelope) != nil || envelope.JSONRPC != "2.0" || envelope.ID != r.nextID {
		return errors.New("RPC returned an invalid JSON-RPC envelope")
	}
	if len(envelope.Error) > 0 && string(envelope.Error) != "null" {
		return fmt.Errorf("RPC method %s returned an error", method)
	}
	if len(envelope.Result) == 0 {
		return errors.New("RPC returned no result")
	}
	if err := json.Unmarshal(envelope.Result, result); err != nil {
		return errors.New("RPC returned an invalid result")
	}
	r.methods[method] = true
	return nil
}

func deFiQuantity(value string) (int64, error) {
	if !strings.HasPrefix(value, "0x") || len(value) < 3 || len(value) > 18 || (len(value) > 3 && value[2] == '0') {
		return 0, errors.New("invalid RPC hex quantity")
	}
	for _, c := range value[2:] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return 0, errors.New("invalid RPC hex quantity")
		}
	}
	n, err := strconv.ParseInt(value[2:], 16, 64)
	if err != nil {
		return 0, errors.New("RPC hex quantity exceeds supported range")
	}
	return n, nil
}

func deFiCodeSummary(raw string) (int, string, error) {
	if !strings.HasPrefix(raw, "0x") || len(raw)%2 != 0 || (len(raw)-2)/2 > deFiCodeBytesLimit {
		return 0, "", errors.New("RPC returned malformed or oversized code")
	}
	code, err := hex.DecodeString(raw[2:])
	if err != nil {
		return 0, "", errors.New("RPC returned malformed code")
	}
	return len(code), fmt.Sprintf("%x", sha256.Sum256(code)), nil
}

func deFiStorageSlot(raw string) (map[string]any, error) {
	if len(raw) != 66 || !strings.HasPrefix(raw, "0x") {
		return nil, errors.New("RPC returned malformed 32-byte storage value")
	}
	word, err := hex.DecodeString(raw[2:])
	if err != nil {
		return nil, errors.New("RPC returned malformed 32-byte storage value")
	}
	var address any
	if bytes.Equal(word[:12], make([]byte, 12)) && !bytes.Equal(word[12:], make([]byte, 20)) {
		address = "0x" + hex.EncodeToString(word[12:])
	}
	return map[string]any{"raw": strings.ToLower(raw), "address": address}, nil
}

func deFiScopedContract(as *db.AssetStore, taskID, chainID int64, address string) error {
	if as == nil || taskID <= 0 {
		return errors.New("DeFi task scope is unavailable")
	}
	key, err := db.ContractScopeKey(chainID, address)
	if err != nil {
		return err
	}
	scopes, err := as.ListTaskScope(taskID)
	if err != nil {
		return errors.New("DeFi task scope could not be checked")
	}
	for _, scope := range scopes {
		if scope.Kind == "contract" && scope.Value == key {
			return nil
		}
	}
	return errors.New("contract is outside this task's explicit scope")
}

func readDeFiDeploymentSnapshot(ctx context.Context, rawURL string, client *http.Client, chainID, blockNumber int64, address string) (map[string]any, error) {
	if chainID <= 0 || blockNumber < 0 {
		return nil, errors.New("chain ID and pinned block are required")
	}
	key, err := db.ContractScopeKey(chainID, address)
	if err != nil {
		return nil, err
	}
	address = strings.TrimPrefix(key, fmt.Sprintf("eip155:%d:", chainID))
	rpc, err := newDeFiRPC(rawURL, client)
	if err != nil {
		return nil, err
	}
	var chainHex string
	if err := rpc.call(ctx, "eth_chainId", []any{}, &chainHex); err != nil {
		return nil, err
	}
	observedChain, err := deFiQuantity(chainHex)
	if err != nil || observedChain != chainID {
		return nil, errors.New("RPC chain ID mismatch or malformed response")
	}
	blockTag := fmt.Sprintf("0x%x", blockNumber)
	readBlock := func() (string, error) {
		var block struct {
			Number string `json:"number"`
			Hash   string `json:"hash"`
		}
		if err := rpc.call(ctx, "eth_getBlockByNumber", []any{blockTag, false}, &block); err != nil {
			return "", err
		}
		number, err := deFiQuantity(block.Number)
		if err != nil || number != blockNumber || len(block.Hash) != 66 || !strings.HasPrefix(block.Hash, "0x") {
			return "", errors.New("RPC did not return the pinned block")
		}
		if _, err := hex.DecodeString(block.Hash[2:]); err != nil {
			return "", errors.New("RPC returned malformed block hash")
		}
		return strings.ToLower(block.Hash), nil
	}
	blockHash, err := readBlock()
	if err != nil {
		return nil, err
	}
	var codeHex string
	if err := rpc.call(ctx, "eth_getCode", []any{address, blockTag}, &codeHex); err != nil {
		return nil, err
	}
	codeBytes, codeHash, err := deFiCodeSummary(codeHex)
	if err != nil {
		return nil, err
	}
	slots := map[string]any{}
	for _, slot := range deFiProxySlots {
		var raw string
		if err := rpc.call(ctx, "eth_getStorageAt", []any{address, slot.key, blockTag}, &raw); err != nil {
			return nil, err
		}
		decoded, err := deFiStorageSlot(raw)
		if err != nil {
			return nil, err
		}
		decoded["slot"] = slot.key
		slots[slot.name] = decoded
	}
	finalHash, err := readBlock()
	if err != nil || finalHash != blockHash {
		return nil, errors.New("pinned block changed during snapshot")
	}
	methods := make([]string, 0, len(rpc.methods))
	for method := range rpc.methods {
		methods = append(methods, method)
	}
	sort.Strings(methods)
	return map[string]any{
		"schema_version": "1.0", "kind": "read_only_deployment_snapshot",
		"created_at": time.Now().UTC().Format(time.RFC3339),
		"chain_id":   chainID, "block_number": blockNumber, "block_hash": blockHash,
		"addresses": []any{map[string]any{
			"address": address, "code_bytes": codeBytes, "code_sha256": codeHash,
			"code_empty": codeBytes == 0, "erc1967_slots": slots,
		}},
		"rpc_methods_used": methods, "slot_specification": deFiSlotSpecURL,
		"limitations": []string{
			"ERC-1967 slot values are hints; proxy behavior and implementation bytecode are not verified by this snapshot.",
			"Only the explicitly scoped address was queried. No beacon implementation() call or other address was followed.",
		},
	}, nil
}

func writeDeFiDeploymentSnapshot(path string, snapshot map[string]any) (string, error) {
	if _, err := os.Stat(path); err == nil {
		return "", errors.New("deployment snapshot already exists")
	} else if !os.IsNotExist(err) {
		return "", err
	}
	blob, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return "", err
	}
	blob = append(blob, '\n')
	tmp, err := os.CreateTemp(filepath.Dir(path), ".deployment-snapshot-*.tmp")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name()) //nolint:errcheck
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if _, err := tmp.Write(blob); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return "", err
	}
	sum := fmt.Sprintf("%x", sha256.Sum256(blob))
	if err := os.WriteFile(path+".sha256", []byte(sum+"  "+filepath.Base(path)+"\n"), 0o600); err != nil {
		return "", err
	}
	return sum, nil
}
