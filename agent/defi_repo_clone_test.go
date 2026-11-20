package agent

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestDeFiGitEnvironmentDropsApplicationSecrets(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "private-key")
	t.Setenv("RPC_URL", "https://rpc.example/private")
	home := t.TempDir()
	env := strings.Join(deFiGitEnvironment(home), "\n")
	if strings.Contains(env, "private-key") || strings.Contains(env, "rpc.example") {
		t.Fatal("application secret was passed to Git")
	}
	if !strings.Contains(env, "HOME="+home) || !strings.Contains(env, "GIT_CONFIG_NOSYSTEM=1") {
		t.Fatal("Git environment is not isolated")
	}
}

func TestDeFiRepositoryScopePinsRevision(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTaskWithOptions("repository", "review", db.TaskCreateOptions{ReviewMode: "defi"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID) //nolint:errcheck
	assets := d.Assets()
	url := "https://github.com/example/protocol"
	if _, err := assets.AddAgentScope(task.ID, "repository", url+"#v1.0.0", "test", "manual"); err != nil {
		t.Fatal(err)
	}
	_, revision, err := scopedDeFiRepository(assets, task.ID, url, "")
	if err != nil || revision != "v1.0.0" {
		t.Fatalf("scoped revision = %q, %v", revision, err)
	}
	if _, _, err := scopedDeFiRepository(assets, task.ID, url, "v2.0.0"); err == nil {
		t.Fatal("out-of-scope revision accepted")
	}
	if _, _, err := scopedDeFiRepository(assets, task.ID, "https://github.com/example/other", "v1.0.0"); err == nil {
		t.Fatal("out-of-scope repository accepted")
	}
	if _, _, err := scopedDeFiRepository(assets, task.ID, url, "--upload-pack=/bin/sh"); err == nil {
		t.Fatal("Git option accepted as a revision")
	}
}

func TestDeFiGitCheckoutCommandSequence(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git unavailable")
	}
	root := t.TempDir()
	home := filepath.Join(root, "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(root, "source")
	if _, err := runDeFiGit(context.Background(), root, home, "init", source); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "Vault.sol"), []byte("contract Vault {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runDeFiGit(context.Background(), root, home, "-C", source, "add", "Vault.sol"); err != nil {
		t.Fatal(err)
	}
	if _, err := runDeFiGit(context.Background(), root, home, "-c", "user.name=review", "-c", "user.email=review@example.test", "-C", source, "commit", "-m", "initial"); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(root, "destination")
	if _, err := runDeFiGit(context.Background(), root, home, "-c", "protocol.file.allow=always", "clone", "--no-checkout", "--depth", "1", "--", source, destination); err != nil {
		t.Fatal(err)
	}
	if _, err := runDeFiGit(context.Background(), root, home, "-c", "protocol.file.allow=always", "-C", destination, "fetch", "--depth", "1", "origin", "--", "HEAD"); err != nil {
		t.Fatal(err)
	}
	if _, err := runDeFiGit(context.Background(), root, home, "-C", destination, "checkout", "--detach", "FETCH_HEAD"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(destination, "Vault.sol")); err != nil {
		t.Fatal(err)
	}
}
