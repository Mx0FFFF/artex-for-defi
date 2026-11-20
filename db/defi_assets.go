package db

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// ContractScopeKey is the canonical EIP-155 identity used by task scopes.
func ContractScopeKey(chainID int64, address string) (string, error) {
	if chainID <= 0 {
		return "", fmt.Errorf("chain_id must be positive")
	}
	address = strings.TrimSpace(address)
	if len(address) != 42 || !strings.HasPrefix(strings.ToLower(address), "0x") {
		return "", fmt.Errorf("address must be a 20-byte 0x-prefixed EVM address")
	}
	for _, c := range address[2:] {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return "", fmt.Errorf("address must be hexadecimal")
		}
	}
	return fmt.Sprintf("eip155:%d:%s", chainID, strings.ToLower(address)), nil
}

// ParseContractScope accepts an EIP-155 contract identity and canonicalizes it.
func ParseContractScope(value string) (int64, string, string, error) {
	parts := strings.Split(strings.TrimSpace(value), ":")
	if len(parts) != 3 || !strings.EqualFold(parts[0], "eip155") {
		return 0, "", "", fmt.Errorf("contract scope must be eip155:<chain_id>:<address>")
	}
	chainID, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return 0, "", "", fmt.Errorf("invalid chain_id: %w", err)
	}
	key, err := ContractScopeKey(chainID, parts[2])
	if err != nil {
		return 0, "", "", err
	}
	return chainID, strings.ToLower(strings.TrimSpace(parts[2])), key, nil
}

// NormalizeRepositoryURL canonicalizes a remote Git repository identifier.
// Query strings, fragments and credentials are rejected so identity is stable.
func NormalizeRepositoryURL(value string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(value))
	if err != nil || u == nil || !strings.EqualFold(u.Scheme, "https") || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("repository_url must be an HTTPS repository URL without credentials, query or fragment")
	}
	if u.Port() != "" {
		return "", fmt.Errorf("repository_url must not specify a port")
	}
	path := strings.TrimSuffix(strings.TrimRight(u.Path, "/"), ".git")
	if path == "" || path == "/" || strings.Contains(path, "//") {
		return "", fmt.Errorf("repository_url must include a repository path")
	}
	u.Scheme = "https"
	u.Host = strings.ToLower(u.Hostname())
	u.Path = path
	u.RawPath = ""
	return u.String(), nil
}

// RepositoryScopeKey optionally pins repository scope to one source revision.
// A bare URL deliberately covers all revisions and contracts linked to that URL.
func RepositoryScopeKey(repositoryURL, revision string) (string, error) {
	repoURL, err := NormalizeRepositoryURL(repositoryURL)
	if err != nil {
		return "", err
	}
	revision = strings.TrimSpace(revision)
	if revision == "" {
		return repoURL, nil
	}
	if len(revision) > 128 || strings.ContainsAny(revision, "# \t\r\n") {
		return "", fmt.Errorf("revision must be at most 128 characters without whitespace or #")
	}
	return repoURL + "#" + revision, nil
}

func NormalizeRepositoryScope(value string) (string, error) {
	repoURL, revision, pinned := strings.Cut(strings.TrimSpace(value), "#")
	if pinned && revision == "" {
		return "", fmt.Errorf("repository scope revision is empty")
	}
	return RepositoryScopeKey(repoURL, revision)
}

type UpsertContractReq struct {
	ChainID       int64
	Address       string
	ContractName  string
	ProtocolName  string
	RepositoryURL string
	TaskID        int64
}

type UpsertRepositoryReq struct {
	RepositoryURL string
	Revision      string
	ProtocolName  string
	TaskID        int64
}

func (s *AssetStore) withDefiMutation(fn func(*AssetStore) (int64, error)) (int64, error) {
	if s.tx != nil {
		return fn(s)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint:errcheck
	id, err := fn(&AssetStore{db: s.db, company: s.company, tx: tx})
	if err != nil {
		return 0, err
	}
	return id, tx.Commit()
}

func optionalText(s string) any {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	return s
}

func taskIDsLiteral(taskID int64) string {
	if taskID > 0 {
		return fmt.Sprintf("{%d}", taskID)
	}
	return "{}"
}

// UpsertContract stores a chain-specific EVM contract and grants the task only
// this contract as its automatic scope. Address case is normalized for dedup.
func (s *AssetStore) UpsertContract(req UpsertContractReq) (int64, error) {
	key, err := ContractScopeKey(req.ChainID, req.Address)
	if err != nil {
		return 0, err
	}
	address := strings.ToLower(strings.TrimSpace(req.Address))
	repoURL := ""
	if strings.TrimSpace(req.RepositoryURL) != "" {
		repoURL, err = NormalizeRepositoryURL(req.RepositoryURL)
		if err != nil {
			return 0, err
		}
	}
	return s.withDefiMutation(func(scoped *AssetStore) (int64, error) {
		var id int64
		err := scoped.tx.QueryRow(`
INSERT INTO assets(type, chain_id, address, contract_name, protocol_name, repository_url, task_ids)
VALUES ('contract',$1,$2,$3,$4,$5,$6::bigint[])
ON CONFLICT (chain_id, address) WHERE type='contract' DO UPDATE SET
    contract_name=COALESCE(EXCLUDED.contract_name,assets.contract_name),
    protocol_name=COALESCE(EXCLUDED.protocol_name,assets.protocol_name),
    repository_url=COALESCE(EXCLUDED.repository_url,assets.repository_url),
    task_ids=(SELECT ARRAY(SELECT DISTINCT unnest(assets.task_ids || EXCLUDED.task_ids))),
    last_seen=now()
RETURNING id`, req.ChainID, address, optionalText(req.ContractName), optionalText(req.ProtocolName), optionalText(repoURL), taskIDsLiteral(req.TaskID)).Scan(&id)
		if err != nil {
			return 0, err
		}
		if req.TaskID > 0 {
			if err := scoped.upsertTaskScope(TaskScope{TaskID: req.TaskID, Kind: "contract", Value: key}); err != nil {
				return 0, err
			}
		}
		return id, nil
	})
}

// UpsertRepository stores a source repository as a separate review target.
// URL and revision together identify a review target; callers should supply a
// commit hash when they need a reproducible source snapshot.
func (s *AssetStore) UpsertRepository(req UpsertRepositoryReq) (int64, error) {
	repoURL, err := NormalizeRepositoryURL(req.RepositoryURL)
	if err != nil {
		return 0, err
	}
	scopeKey, err := RepositoryScopeKey(repoURL, req.Revision)
	if err != nil {
		return 0, err
	}
	revision := strings.TrimSpace(req.Revision)
	return s.withDefiMutation(func(scoped *AssetStore) (int64, error) {
		var id int64
		err := scoped.tx.QueryRow(`
INSERT INTO assets(type, repository_url, revision, protocol_name, task_ids)
VALUES ('repository',$1,$2,$3,$4::bigint[])
ON CONFLICT (repository_url, (COALESCE(revision,''))) WHERE type='repository' DO UPDATE SET
    protocol_name=COALESCE(EXCLUDED.protocol_name,assets.protocol_name),
    task_ids=(SELECT ARRAY(SELECT DISTINCT unnest(assets.task_ids || EXCLUDED.task_ids))),
    last_seen=now()
RETURNING id`, repoURL, optionalText(revision), optionalText(req.ProtocolName), taskIDsLiteral(req.TaskID)).Scan(&id)
		if err != nil {
			return 0, err
		}
		if req.TaskID > 0 {
			if err := scoped.upsertTaskScope(TaskScope{TaskID: req.TaskID, Kind: "repository", Value: scopeKey}); err != nil {
				return 0, err
			}
		}
		return id, nil
	})
}

