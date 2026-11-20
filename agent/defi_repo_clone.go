package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/google/uuid"
)

var safeDeFiRevision = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/+\-]{0,127}$`)

func scopedDeFiRepository(as *db.AssetStore, taskID int64, rawURL, requestedRevision string) (string, string, error) {
	if as == nil || taskID <= 0 {
		return "", "", errors.New("DeFi task scope is unavailable")
	}
	repoURL, err := db.NormalizeRepositoryURL(rawURL)
	if err != nil {
		return "", "", err
	}
	requestedRevision = strings.TrimSpace(requestedRevision)
	if requestedRevision != "" && (!safeDeFiRevision.MatchString(requestedRevision) || strings.Contains(requestedRevision, "..") || strings.Contains(requestedRevision, "//")) {
		return "", "", errors.New("revision must be a simple commit or Git ref")
	}
	scopes, err := as.ListTaskScope(taskID)
	if err != nil {
		return "", "", errors.New("DeFi task scope could not be checked")
	}
	bareAllowed := false
	pinnedRevision := ""
	for _, scope := range scopes {
		if scope.Kind != "repository" {
			continue
		}
		scopedURL, scopedRevision, pinned := strings.Cut(scope.Value, "#")
		if scopedURL != repoURL {
			continue
		}
		if !pinned {
			bareAllowed = true
			continue
		}
		if !safeDeFiRevision.MatchString(scopedRevision) || strings.Contains(scopedRevision, "..") || strings.Contains(scopedRevision, "//") {
			return "", "", errors.New("scoped revision is not a simple Git ref")
		}
		if requestedRevision == scopedRevision {
			return repoURL, scopedRevision, nil
		}
		if requestedRevision == "" {
			if pinnedRevision != "" && pinnedRevision != scopedRevision {
				return "", "", errors.New("multiple scoped revisions; specify one explicitly")
			}
			pinnedRevision = scopedRevision
		}
	}
	if pinnedRevision != "" {
		return repoURL, pinnedRevision, nil
	}
	if bareAllowed {
		return repoURL, requestedRevision, nil
	}
	return "", "", errors.New("repository or revision is outside this task's explicit scope")
}

func deFiGitEnvironment(home string) []string {
	allowed := map[string]bool{"PATH": true, "LANG": true, "LC_ALL": true, "USER": true}
	var out []string
	for _, item := range os.Environ() {
		key, _, _ := strings.Cut(item, "=")
		if allowed[key] {
			out = append(out, item)
		}
	}
	return append(out, "HOME="+home, "TMPDIR="+home, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_TERMINAL_PROMPT=0", "GIT_LFS_SKIP_SMUDGE=1", "GIT_SSH_COMMAND=/bin/false")
}

func runDeFiGit(ctx context.Context, workDir, home string, args ...string) (string, error) {
	command := append([]string{
		"-c", "protocol.file.allow=never", "-c", "protocol.ext.allow=never",
		"-c", "protocol.ssh.allow=never", "-c", "http.followRedirects=false",
		"-c", "core.hooksPath=/dev/null",
	}, args...)
	cmd := exec.CommandContext(ctx, "git", command...)
	configureDeFiProcessGroup(cmd)
	cmd.Dir = workDir
	cmd.Env = deFiGitEnvironment(home)
	var stdout, stderr limitedToolBuffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		killDeFiProcessGroup(cmd)
		return "", errors.New("Git operation timed out or was cancelled")
	}
	if stdout.truncated || stderr.truncated {
		return "", errors.New("Git output exceeded the limit")
	}
	if err != nil {
		return "", fmt.Errorf("Git operation failed: %v", err)
	}
	return strings.TrimSpace(stdout.String()), nil
}

// cloneDeFiRepository does not execute repository hooks, filters, or submodules.
// The returned commit, not a mutable branch/tag, is the source identity.
func cloneDeFiRepository(ctx context.Context, as *db.AssetStore, taskID int64, taskRoot, rawURL, revision string) (string, string, error) {
	repoURL, scopedRevision, err := scopedDeFiRepository(as, taskID, rawURL, revision)
	if err != nil {
		return "", "", err
	}
	parent := filepath.Join(taskRoot, "repositories")
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return "", "", err
	}
	id := uuid.NewString()
	destination := filepath.Join(parent, id)
	home := filepath.Join(taskRoot, ".git-home", id)
	if err := os.MkdirAll(home, 0o700); err != nil {
		return "", "", err
	}
	defer os.RemoveAll(home) //nolint:errcheck
	complete := false
	defer func() {
		if !complete {
			_ = os.RemoveAll(destination)
		}
	}()
	callCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if _, err := runDeFiGit(callCtx, taskRoot, home, "clone", "--no-checkout", "--depth", "1", "--", repoURL, destination); err != nil {
		return "", "", err
	}
	if scopedRevision != "" {
		if _, err := runDeFiGit(callCtx, taskRoot, home, "-C", destination, "fetch", "--depth", "1", "origin", "--", scopedRevision); err != nil {
			return "", "", err
		}
		if _, err := runDeFiGit(callCtx, taskRoot, home, "-C", destination, "checkout", "--detach", "FETCH_HEAD"); err != nil {
			return "", "", err
		}
	} else if _, err := runDeFiGit(callCtx, taskRoot, home, "-C", destination, "checkout", "--detach", "HEAD"); err != nil {
		return "", "", err
	}
	commit, err := runDeFiGit(callCtx, taskRoot, home, "-C", destination, "rev-parse", "--verify", "HEAD")
	if err != nil || !regexp.MustCompile(`^[0-9a-f]{40,64}$`).MatchString(commit) {
		return "", "", errors.New("Git checkout did not resolve to a commit")
	}
	if err := os.Chmod(destination, 0o700); err != nil {
		return "", "", err
	}
	complete = true
	return destination, commit, nil
}
