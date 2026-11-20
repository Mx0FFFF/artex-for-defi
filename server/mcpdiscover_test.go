package server

import (
	"context"
	"encoding/json"
	"os/exec"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func TestStdioMCPServiceCredentials(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable")
	}
	t.Setenv("RPC_URL", "test-service-value")
	t.Setenv("OPENAI_API_KEY", "test-service-value")
	script := `import json, os, sys
assert not os.environ.get("RPC_URL")
assert os.environ.get("OPENAI_API_KEY", "") == sys.argv[1]
message = json.loads(sys.stdin.readline())
print(json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": {}}), flush=True)
sys.stdin.readline()
`
	for _, explicit := range []string{"", "test-mcp-value"} {
		args, err := json.Marshal([]string{"-c", script, explicit})
		if err != nil {
			t.Fatal(err)
		}
		server := db.MCPServer{Transport: "stdio", Name: "test", Command: python, Args: args}
		if explicit != "" {
			server.Env = json.RawMessage(`{"OPENAI_API_KEY":"test-mcp-value"}`)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		client, err := connectMCP(ctx, &server)
		cancel()
		if err != nil {
			t.Fatalf("stdio credential check failed: %v", err)
		}
		client.Close()
	}
}
