# Reproducible DeFi evidence workflow

This page describes the adapter files and receipt contract. It does not establish that a claimed exploit is true. Use an isolated copy of the target source and a separate output directory. Never put production signing keys in the review environment.

## From source to a candidate

```bash
python3 ${SKILL_DIR}/scripts/catalog.py tags
python3 ${SKILL_DIR}/scripts/catalog.py select --track evm --protocol vault --feature donations --format json --output "$OUT/selection.json"
python3 ${SKILL_DIR}/scripts/review_ledger.py init --selection "$OUT/selection.json" --output "$OUT/ledger.json"
python3 ${SKILL_DIR}/scripts/run_analysis.py run forge-build --project "$PROJECT" --output-dir "$OUT/runs"
python3 ${SKILL_DIR}/scripts/inventory.py "$PROJECT" --output "$OUT/inventory.json"
python3 ${SKILL_DIR}/scripts/run_analysis.py run slither --project "$PROJECT" --output-dir "$OUT/runs"
```

The catalog's full 43-card ledger and the review ledger must survive compaction and worker handoff. `deselected` means not retrieved; `blocked` needs an explicit cause. A Slither result with candidate findings has status `findings`, which is **not** an ARTEX `report_finding`.

## Reproduce and challenge

Write a protocol-specific test with an intended property, a reachable setup, the adversarial action, a measurable state/asset delta, and a nearby negative control. Run a selected test through the wrapper:

```bash
python3 ${SKILL_DIR}/scripts/run_analysis.py run forge-test --project "$PROJECT" --output-dir "$OUT/runs" --match-contract "$TEST_CONTRACT" --match-test "$TEST_FUNCTION"
```

The command returns a `result.json` path. A passing nonempty suite includes a source snapshot, manifest, stdout/stderr, `replay_receipt.json`, and `evidence_artifact_refs`. The result's status `pass` proves only that the selected test passed in that environment. `incomplete` covers build failure, FFI refusal, empty suites, unavailable tools, output cap and timeout. Preserve its cause in the coverage ledger.

For a scoped onchain address, use the fixed `defi_analysis` actions `verified-source-fetch` and `deployment-snapshot` first. Pass the same `chain_id`, `block_number`, and `address` to the local `forge-test` action. After it passes, call `deployment-bind` with that run's `result.json`, the pinned snapshot JSON, and the saved Sourcify response JSON. For a confirmed record, bind the **final independent replay result**; its artifact root is separate from the primary run. Set `source_prefix` only if every Sourcify source path appears below that exact prefix in the retained source archive. The action copies both external artifacts into the test run and writes `deployment_binding.json` there. `evidence-from-run` includes and rechecks it automatically, marking `source_bytecode_match=verified` only when Sourcify reported `runtimeMatch=exact_match`, the runtime bytes hash to the pinned code, and every verified source file matches the test snapshot. Any mismatch leaves the claim unverified; do not manually set the field to `verified`.

This strict source identity still does not establish that the local test imported those exact files, live exploitability, economic feasibility, proxy implementation correspondence, or a fork replay. Inspect compiler inputs and test imports before promoting a claim. A proxy's implementation must be separately scoped and checked at the same block. The current fixed runner remains offline; a manually run fork is exploratory evidence only and `fork_test` cannot be promoted by the validator.
`report_finding` rejects a record with chain context unless its binding names an address explicitly in the task's contract scope. To report a source-only issue before deployment correspondence is established, keep chain context null and state the deployment limit plainly.

Symbolic properties: `run_analysis.py run halmos --match-test check_<prop>` symbolically executes `check_`-prefixed property functions and writes `halmos.json` into the run directory as a hashed evidence artifact. Status `findings` means at least one counterexample with a concrete model — a candidate, not a finding; `pass` is a bounded proof within halmos's loop/array/bytes limits; `incomplete` means a property could not be decided (solver timeout or unavailable) and is never a clean result. Reproduce any counterexample with a concrete `forge-test` and the normal replay receipt before promoting past `statically_supported`; a halmos pass records `statically_supported` coverage for the property, not `reproduced`.

Generate a hypothesis draft by default:

```bash
python3 ${SKILL_DIR}/scripts/evidence.py from-run "$PRIMARY_RESULT" --output "$PRIMARY_DIR/hypothesis.json"
```

To request `reproduced`, supply a `details.json` with **observed** semantics. This synthetic example shows the required *shape*, not a real protocol finding:

```json
{
  "id": "SYNTH-01",
  "title": "Synthetic unauthorized claim transfer",
  "detector_ids": ["EVM-01"],
  "root_cause": "The local fixture omits a caller-owner check",
  "attacker_capabilities": ["Call the public withdrawFor entry point"],
  "preconditions": ["The fixture has a funded claim for another actor"],
  "locations": ["src/SyntheticVault.sol:20"],
  "violated_property": "Only the claim owner or an authorized delegate can move the claim",
  "reachability_explanation": "An ordinary caller reaches withdrawFor in the local fixture",
  "before_state": {"victim_claim": "10", "attacker_claim": "0"},
  "after_state": {"victim_claim": "0", "attacker_claim": "10"},
  "impact": {"category": "unauthorized_control", "description": "Ten synthetic claim units moved; no real funds", "profit_claimed": false},
  "false_positive_review": ["A fixed variant checks owner authorization and rejects the same call"],
  "limitations": ["Synthetic fixture only; no deployed protocol claim"]
}
```

```bash
python3 ${SKILL_DIR}/scripts/evidence.py from-run "$PRIMARY_RESULT" --status reproduced --details "$OUT/details.json" --output "$PRIMARY_DIR/reproduced.json"
python3 ${SKILL_DIR}/scripts/evidence.py validate "$PRIMARY_DIR/reproduced.json" --artifact-root "$PRIMARY_DIR"
```

For `confirmed`, a separate reviewer challenges the setup and interpretation. A second clean runner invocation can produce a distinct `independent_replay` receipt using `--reuse-manifest "$PRIMARY_DIR/manifest.json" --independent-verifier "$REVIEWER_ID"`. The second run copies the primary artifacts into one self-contained artifact root and adds the separate replay log and receipt. The record must point to both sets of hashed refs and pass `evidence.py validate`. A verifier label and two logs do **not** prove independent reasoning; that requires an actual reviewer or independently checkable proof.

The full Draft 2020-12 requirements are in `data/finding_schema.json`. `review_ledger.py status --status reproduced|confirmed` requires the matching validated record and artifact root. After a valid confirmed record and review, summarize the mechanism and record path in ARTEX `report_finding`; keep the complete JSON and artifacts in the task workspace.

## Economic claims

`evidence.py ledger` accepts exact decimal strings and values every initial/terminal asset and liability at an **independent executable price**. It consolidates all attacker-controlled accounts, subtracts outside contributions and off-balance costs, adds outside withdrawals back, and reconciles `borrowed + fee = repaid + outstanding`. For `profit_claimed=true`, the hashed ledger and price evidence must be attached to the finding record and net profit must be positive. Fixture mints and manipulated oracle quotes are never counted as realized profit. An exploit can still be real without positive attacker profit when it causes unauthorized control, insolvency, frozen funds or incorrect settlement.

The evaluator-only ground truth for `evaluate.py` belongs outside the worker's workspace. Keep vulnerable and fixed cases in one protocol-family split; compare only independently adjudicated root-cause matches, and report undefined denominators as null.

```bash
python3 ${SKILL_DIR}/scripts/evaluate.py --cases "$EVALUATOR_ONLY/cases.json" --predictions "$EVALUATOR_ONLY/adjudicated.json" --output "$EVALUATOR_ONLY/metrics.json"
```

`cases.json` contains a `cases` array with `case_id`, `split` (`development`, `private_validation`, or `sealed_test`), `protocol_family`, `expected_root_causes` (evaluator IDs), and optional `leakage_groups` for shared exploit/root-cause families. `adjudicated.json` contains a `predictions` array with `case_id`, `finding_id`, evidence `status`, and evaluator-assigned `adjudicated_root_cause_id` (null for a false claim); optional nonnegative `cost_usd` and `duration_seconds` support operating-cost metrics. The scorer refuses family leakage across splits and counts duplicate confirmed reports as false positives. It computes arithmetic only; an independent evaluator must decide the matches and whether each evidence record is valid.

In `adjudicated.json`, record case outcomes separately from individual predictions. The optional `case_runs` array accepts one entry per case, such as `{"case_id":"control-1","status":"completed"}`. Use `completed` when the planned review finished, `incomplete` for a partially finished review, `blocked` for a review that could not proceed, and `unknown` when completion cannot be established. An entry with no status or a prediction with no run entry counts as unknown. A case with neither a run entry nor a prediction counts as missing.

For each split, `case_runs.completion_rate` divides documented completions by all manifest cases. `case_runs.completed_clean_case_false_positive_rate` uses only completed controls with empty ground truth. The historical `clean_case_false_positive_rate` includes every control in its denominator, even those with missing results. A zero denominator yields `null`.
