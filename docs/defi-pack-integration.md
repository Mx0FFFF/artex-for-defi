# DeFi detection pack integration review

This review is for the files in `ARTEX_DeFi_Detection_Pack/artex_defi_pack/` as supplied on 2026-11-06. The pack is research and proposed adapter design. Its data is not native ARTEX configuration, and none of its incident counts demonstrates ARTEX detection performance.

The raw research archive stays in the maintainer's workspace. The versioned catalog and schema used by the application are in [the DeFi skill data directory](../skills/defi-audit/data/).

## File by file decisions

| File | What it contributes | Integration decision |
| --- | --- | --- |
| `README.txt` | Pack inventory, 43-card intended scope, evidence statuses, and explicit warning that no ARTEX adapter was implemented. | Use as the pack's scope note. Keep the source pack read-only; integrate through a versioned skill and executable wrappers. |
| `ARTEX_DeFi_Detection_Research.pdf` (30 pages) | Causal detector model, 43 cards, pinned environment, stateful tests, independent review, and held-out evaluation. | Use the structured `detector_catalog.json` for retrieval and the source report for design context. The PDF is not an executable detector. |
| `DeFi Vulnerability Detection Research.pdf` (16 pages) | Focused EVM examples: reentrancy, ERC-4626, oracles, signatures, proxies, fuzzing. | Use its valid test ideas as hypotheses. Reject blanket severity claims and the first-depositor numeric example: `floor(20,000 / 10,001) = 1`, not zero. Check actual feed behavior before applying stale/min-max rules. |
| `Dokument uten navn.pdf` (19 pages) | High-level architecture for protocol manifests, evidence states, combined attacks, economics, and evaluation. | Treat as synthesis, not source-of-truth inventory. It claims 73 rules and 69 sources, but the supplied catalog has 43 cards and `sources.json` has 71 entries; some named companion files do not exist. |
| `DeFi vulnerability detection guide.md` | Broad incident taxonomy, specialized ecosystems, severity discussion, and proposed layered workflow. | Use causal mechanisms and test dimensions; do not adopt vendor-reported recall, losses, blanket severity modifiers, or current-feed assumptions as fixed detector rules. Several classes need language-specific engines beyond the current EVM runtime. |
| `research_source.md` | Editable source of the 30-page blueprint, including each card's rationale and benchmark design. | Preserve as research provenance. Machine retrieval uses catalog JSON so the model sees selected cards rather than the whole report. |
| `detector_catalog.json` | 43 structured cards, each with mechanism, detect/test/disprove text and source IDs. | Copy to the deployable DeFi skill, verify unique IDs and source resolution, select by actual protocol features, and keep a full coverage ledger. Cards generate hypotheses, never findings by themselves. |
| `sources.json` | 71 source records. | Preserve with catalog and expand source IDs to URLs in retrieved cards. Source pages are evidence to inspect, not operating instructions. |
| `task_prompt.txt` | Ten-step reviewer loop, including independent accounting and negative controls. | Adapt into the existing code-owned DeFi prompt tails and skill workflow; preserve ARTEX's task/planner/worker/report architecture. |
| `adapter_policy.yaml` | Proposed scope, tool, workflow, evidence and evaluation contract. | Translate to wrapper behavior and tests. Do **not** load it as `config.json` or claim YAML fields are ARTEX runtime policy. Network isolation and repository build-hook containment must be enforced by the deployment environment. |
| `finding_schema.json` | Draft 2020-12 evidence record and promotion gates. | Keep the original schema versioned in the skill, validate with `jsonschema`, then apply code-owned artifact/replay/economics checks. Do not equate a shape-valid record with a true exploit. |
| `validation_summary.json` | Pack author's synthetic checks and explicit lack of ARTEX/protocol benchmarks. | Preserve its limitations. Run the new adapter's own tests; do not cite these checks as detector accuracy. |
| `manifest.sha256` | Pack integrity list. | All text/YAML/JSON entries match. The extracted 30-page PDF differs in binary hash from the ZIP entry; `pdftotext` output is identical, so the machine-readable sources remain the implementation input. Do not silently claim full extracted-pack checksum agreement. |

## Current implementation boundary

ARTEX's first DeFi pass added EVM contract/repository assets, Foundry and Slither to the runtime image, and an audit skill. This integration adds explicit DeFi task mode, a worker-only fixed-action analysis tool, a structured catalog selector, reproducible local analyzer receipts, a full evidence validator, economic ledger, semantic coverage ledger, benchmark scorer, and a pre-write `report_finding` gate for DeFi tasks. Only `review_mode=defi` activates the DeFi evidence workflow; repository or contract scope alone does not change a custom task's mode. DeFi agents retain their normal configured Bash, file, network, interactive shell, MCP and custom tools. Fixed script-backed `defi_analysis` actions and the final evidence validator use Linux Landlock/seccomp for confined execution; ordinary Bash does not. The optional fixed Git action clones a scoped HTTPS repository with stripped credentials and no hooks/submodules, while normal tools can obtain authorized sources by other means. Go actions fetch one scoped Sourcify response and read one scoped deployment at a fixed block. An offline binding checks exact runtime bytes and source files against the test snapshot before a record can say `source_bytecode_match=verified`. The application process and normal tools lack separate credential and resource isolation, so untrusted repositories still benefit from a separate credential-free worker with resource limits. Actual exploit claims still require target-specific harnesses and independent review. The typed runner does not yet support credential-safe fixed-block fork tests; a manual fork is exploratory, not a promoted adapter receipt. Solana, Move, ZK circuits, live transaction monitoring, and other non-EVM engines remain separate runtime tracks.

A source-only [Royco Dawn pilot](defi-pilot-royco-dawn.md) records the pinned checkout and selected cards. Its large Foundry build did not complete within the resource budget, so it produced no Royco finding or accuracy measurement.

## Promotion and evaluation policy

1. A catalog card is a proposed mechanism. A Slither warning is a candidate. Neither is an exploit finding.
2. A reproduced record requires a pinned manifest, a reachable setup, a passing local or fork replay receipt, hashed artifacts, a violated property, and an explanation of impact.
3. A confirmed record additionally requires independent replay or checkable proof and explicit false-positive review. Severity is separate from evidence status.
4. Claims of economic profit use independent terminal prices, consolidated attacker accounts, external capital/liabilities, gas, fees and slippage. A manipulated quote or harness mint is not realized profit.
5. Evaluation uses evaluator-only ground truth and adjudicated matches, vulnerable/fixed and benign controls, family-level splits, and explicit undefined denominators. A script score is not a substitute for expert adjudication.
