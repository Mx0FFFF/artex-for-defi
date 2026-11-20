package config

import (
	"runtime"
	"strings"
)

// These service settings may contain credentials, including in endpoint URLs.
var serviceEnvKeys = [...]string{
	"ARTEX_PG_DSN", "POSTGRES_PASSWORD", "PGPASSWORD",
	"ANTHROPIC_API_KEY", "OPENAI_API_KEY", "OPENROUTER_API_KEY",
	"ARTEX_LLM_BASE_URL", "ARTEX_LLM_PROXY", "RPC_URL",
}

// MaskServiceEnv appends blank overrides to a shell or script environment.
// The agent SDK layers overrides onto the parent environment at spawn time.
func MaskServiceEnv(env []string) []string {
	for _, key := range serviceEnvKeys {
		env = append(env, key+"=")
	}
	return env
}

// StdioMCPEnv masks service credentials unless explicitly set for this server.
func StdioMCPEnv(configured map[string]string) map[string]string {
	env := make(map[string]string, len(serviceEnvKeys)+len(configured))
	for _, key := range serviceEnvKeys {
		env[key] = ""
	}
	for key, value := range configured {
		if runtime.GOOS == "windows" {
			key = strings.ToUpper(key)
		}
		env[key] = value
	}
	return env
}
