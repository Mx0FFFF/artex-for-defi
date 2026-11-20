package server

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/Autumn-27/artex/intercept"
)

// approveDeFiFinding queues a hash-bound claim for an operator. The caller
// revalidates the record after the decision and before writing the finding.
func (s *Server) approveDeFiFinding(ctx context.Context, taskID int64, recordRef string, raw json.RawMessage) (bool, error) {
	if s.m == nil || s.m.interceptor == nil {
		return false, errors.New("interceptor unavailable")
	}
	var claim struct {
		Name         string `json:"name"`
		Severity     string `json:"severity"`
		VulnClass    string `json:"vulnclass"`
		Summary      string `json:"summary"`
		Record       string `json:"evidence_record"`
		ArtifactRoot string `json:"artifact_root"`
	}
	if err := json.Unmarshal(raw, &claim); err != nil {
		return false, err
	}
	approvalInput, err := json.Marshal(map[string]any{
		"task_id": taskID, "record_ref": recordRef, "name": claim.Name,
		"severity": claim.Severity, "vulnclass": claim.VulnClass,
		"summary": claim.Summary, "evidence_record": claim.Record,
		"artifact_root": claim.ArtifactRoot,
	})
	if err != nil {
		return false, err
	}
	decision := intercept.Decision{Action: "ask", Message: "DeFi finding 需要操作员核对复现、影响和独立复核：" + recordRef}
	return s.m.interceptor.HandleAsk(ctx, intercept.ConvIDFromContext(ctx), decision, "report_finding", approvalInput), nil
}
