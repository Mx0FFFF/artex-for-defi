package agent

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
	actool "github.com/Autumn-27/norma/tool"
)

// Wired by server.New from the actual skillDir passed to the server. A nil
// resolver fails closed for DeFi reporting.
var DeFiEvidenceScriptPath func() string

// Wired by the server to the operator approval queue. A valid JSON record and
// a self-supplied verifier label are not an independent finding review.
var DeFiFindingApproval func(context.Context, int64, string, json.RawMessage) (bool, error)

// A source-only claim may omit chain context. A claim tied to a deployment must
// carry an exact binding for a contract explicitly in this task's scope.
func validateDeFiFindingScope(ctx context.Context, as *db.AssetStore, taskID int64, record, root string) error {
	taskRoot, err := defiTaskWorkspace(ctx, taskID)
	if err != nil {
		return err
	}
	recordPath, err := confinedPath(taskRoot, record, false)
	if err != nil {
		return err
	}
	artifactRoot, err := confinedPath(taskRoot, root, true)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(recordPath)
	if err != nil || len(raw) > 2<<20 {
		return errors.New("DeFi 证据记录不可读或过大")
	}
	var meta struct {
		Environment struct {
			Chain               string `json:"chain"`
			SourceBytecodeMatch string `json:"source_bytecode_match"`
		} `json:"environment"`
	}
	if err := json.Unmarshal(raw, &meta); err != nil {
		return err
	}
	if meta.Environment.Chain == "" {
		return nil
	}
	if meta.Environment.SourceBytecodeMatch != "verified" {
		return errors.New("DeFi 链上漏洞缺少已验证的源码/字节码绑定")
	}
	bindingPath, err := confinedPath(artifactRoot, "deployment_binding.json", false)
	if err != nil {
		return errors.New("DeFi 链上漏洞缺少 deployment_binding.json")
	}
	bindingRaw, err := os.ReadFile(bindingPath)
	if err != nil || len(bindingRaw) > 2<<20 {
		return errors.New("DeFi 部署绑定不可读或过大")
	}
	var binding struct {
		ChainID int64  `json:"chain_id"`
		Address string `json:"address"`
	}
	if err := json.Unmarshal(bindingRaw, &binding); err != nil || meta.Environment.Chain != strconv.FormatInt(binding.ChainID, 10) {
		return errors.New("DeFi 部署绑定链 ID 与证据记录不一致")
	}
	if err := deFiScopedContract(as, taskID, binding.ChainID, binding.Address); err != nil {
		return fmt.Errorf("DeFi 部署地址不在当前任务范围: %w", err)
	}
	return nil
}

func requireDeFiFindingApproval(ctx context.Context, taskID int64, recordRef string,
	input json.RawMessage, approve func(context.Context, int64, string, json.RawMessage) (bool, error)) error {
	if approve == nil {
		return errors.New("DeFi 漏洞人工审批器不可用；未登记漏洞")
	}
	allowed, err := approve(ctx, taskID, recordRef, input)
	if err != nil {
		return fmt.Errorf("DeFi 漏洞人工审批失败: %w", err)
	}
	if !allowed {
		return errors.New("DeFi 漏洞未获人工批准；未登记漏洞")
	}
	return nil
}

// withDeFiFindingSchema runs after DB tool overrides so existing installations
// see these optional fields without replacing any user-edited description.
func withDeFiFindingSchema(tool actool.CoreTool) actool.CoreTool {
	raw, err := json.Marshal(tool.InputSchema())
	if err != nil {
		return tool
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		return tool
	}
	props, ok := schema["properties"].(map[string]any)
	if !ok {
		return tool
	}
	props["evidence_record"] = str("DeFi 任务必填：状态为 confirmed、已通过 evidence.py validate 的结构化发现 JSON，位于本任务工作区")
	props["artifact_root"] = str("DeFi 任务必填：上述记录引用的工件根目录，位于本任务工作区")
	return DecorateTool(tool, tool.Description(), schema)
}

func defiTaskWorkspace(ctx context.Context, taskID int64) (string, error) {
	review, err := intercept.BuildReviewInput(ctx, "report_finding", json.RawMessage(`{}`))
	if err != nil {
		return "", err
	}
	wdir := review.WorkingDir
	if wdir == "" {
		return "", errors.New("DeFi 漏洞上报缺少任务工作目录")
	}
	current, err := filepath.EvalSymlinks(wdir)
	if err != nil {
		return "", err
	}
	want := strconv.FormatInt(taskID, 10)
	for {
		parent := filepath.Dir(current)
		if filepath.Base(current) == want && filepath.Base(parent) == "tasks" {
			return current, nil
		}
		if parent == current {
			return "", errors.New("DeFi 漏洞上报工作目录不属于当前任务")
		}
		current = parent
	}
}

// validateDeFiFindingRecord is a code-owned pre-write gate. The Python schema
// validator checks replay/artifact consistency; this Go path also checks task
// ownership, confirmed status and severity before any finding can be persisted.
func validateDeFiFindingRecord(ctx context.Context, taskID int64, record, root, severity, vulnClass, name, summary string) (string, error) {
	switch severity {
	case "critical", "high", "medium", "low":
	default:
		return "", errors.New("DeFi 漏洞严重度必须为 critical/high/medium/low")
	}
	taskRoot, err := defiTaskWorkspace(ctx, taskID)
	if err != nil {
		return "", err
	}
	path, err := confinedPath(taskRoot, record, false)
	if err != nil {
		return "", fmt.Errorf("evidence_record: %w", err)
	}
	artifactRoot, err := confinedPath(taskRoot, root, true)
	if err != nil {
		return "", fmt.Errorf("artifact_root: %w", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if info.Size() > 2<<20 {
		return "", errors.New("DeFi 证据记录超过 2 MiB")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var meta struct {
		Status      string   `json:"status"`
		Severity    string   `json:"severity"`
		Title       string   `json:"title"`
		DetectorIDs []string `json:"detector_ids"`
		Impact      struct {
			Description string `json:"description"`
		} `json:"impact"`
	}
	if err := json.Unmarshal(raw, &meta); err != nil {
		return "", err
	}
	if meta.Status != "confirmed" {
		return "", errors.New("DeFi report_finding 仅接受独立复核后的 confirmed 记录")
	}
	if meta.Severity != severity {
		return "", errors.New("DeFi 证据记录 severity 与 report_finding 不一致")
	}
	matched := false
	for _, id := range meta.DetectorIDs {
		if vulnClass == id {
			matched = true
			break
		}
	}
	if !matched {
		return "", errors.New("DeFi report_finding 的 vulnclass 必须是证据记录中的 detector_ids 之一")
	}
	title := strings.TrimSpace(meta.Title)
	impact := strings.TrimSpace(meta.Impact.Description)
	if title == "" || impact == "" || strings.TrimSpace(name) != title {
		return "", errors.New("DeFi report_finding 的 name 必须与证据记录 title 完全一致")
	}
	if strings.TrimSpace(summary) != title+": "+impact {
		return "", errors.New("DeFi report_finding 的 summary 必须为 title + ': ' + impact.description")
	}
	if DeFiEvidenceScriptPath == nil {
		return "", errors.New("DeFi 证据验证器未配置")
	}
	script := DeFiEvidenceScriptPath()
	if info, err := os.Stat(script); err != nil || !info.Mode().IsRegular() {
		return "", errors.New("DeFi 证据验证器不可用")
	}
	callCtx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	commandArgs, err := deFiSandboxCommand(filepath.Dir(script), taskRoot, taskRoot, script,
		"validate", path, "--artifact-root", artifactRoot)
	if err != nil {
		return "", err
	}
	cmd := exec.CommandContext(callCtx, "python3", commandArgs...)
	configureDeFiProcessGroup(cmd)
	cmd.Dir = taskRoot
	cmd.Env = defiToolEnvironment()
	var stdout, stderr limitedToolBuffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		if callCtx.Err() != nil {
			killDeFiProcessGroup(cmd)
		}
		return "", fmt.Errorf("DeFi 证据校验失败: %v %s %s", err, stdout.String(), stderr.String())
	}
	if stdout.truncated || stderr.truncated {
		return "", errors.New("DeFi 证据校验器输出过大")
	}
	var verdict struct {
		OK bool `json:"ok"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &verdict); err != nil || !verdict.OK {
		return "", errors.New("DeFi 证据校验器没有返回有效通过结果")
	}
	current, err := os.ReadFile(path)
	if err != nil || sha256.Sum256(current) != sha256.Sum256(raw) {
		return "", errors.New("DeFi 证据记录在校验期间发生变化")
	}
	sum := sha256.Sum256(raw)
	rel, err := filepath.Rel(taskRoot, path)
	if err != nil || strings.HasPrefix(rel, "..") {
		return "", errors.New("DeFi 证据路径不在当前任务中")
	}
	return fmt.Sprintf("DeFi evidence_record: %s#sha256=%x", filepath.ToSlash(rel), sum), nil
}
