#!/usr/bin/env python3
"""Validate DeFi evidence and calculate a conservative, exact economic ledger.

The JSON Schema checks shape. These additional gates check local artifact bytes and
internal consistency. Neither a JSON file nor this CLI can prove that a test was
run in a trusted sandbox or that a claimed market price was executable.

Artifact references use ``relative/path#sha256=<64 lowercase hex digits>`` and
are resolved beneath --artifact-root. A replay receipt is emitted by the trusted
runner, not by this validator. See validate_replay_receipt for its JSON contract.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation, localcontext
from pathlib import Path
from typing import Any

try:
    from jsonschema import Draft202012Validator, FormatChecker
except ImportError as exc:  # pragma: no cover - environment diagnostic
    raise SystemExit("jsonschema is required: python3 -m pip install jsonschema") from exc


SCHEMA_PATH = Path(__file__).resolve().parent.parent / "data" / "finding_schema.json"
HASH_REF = re.compile(r"^(?P<path>[^#]+)#sha256=(?P<digest>[0-9a-f]{64})$")
CONFIRMABLE = {"reproduced", "confirmed"}
TEST_KINDS = {"local_test", "fork_test"}
PROOF_KINDS = {"formal_counterexample", "proof"}
MAX_JSON_BYTES = 2 * 1024 * 1024


class EvidenceError(ValueError):
    """Evidence or ledger does not satisfy a code-owned gate."""


@dataclass(frozen=True)
class Artifact:
    ref: str
    path: Path
    digest: str


def read_json(path: Path, *, max_bytes: int = MAX_JSON_BYTES) -> Any:
    if not path.is_file() or path.stat().st_size > max_bytes:
        raise EvidenceError(f"JSON artifact missing or exceeds {max_bytes} bytes: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"invalid JSON artifact {path}: {exc}") from exc


def _safe_relative_path(raw: str) -> Path:
    if not raw or "\\" in raw or "\x00" in raw or ":" in raw:
        raise EvidenceError(f"unsafe artifact path: {raw!r}")
    parts = raw.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise EvidenceError(f"unsafe artifact path: {raw!r}")
    path = Path(*parts)
    if path.is_absolute():
        raise EvidenceError(f"absolute artifact path: {raw!r}")
    return path


def artifact_ref(ref: str, root: Path) -> Artifact:
    match = HASH_REF.fullmatch(ref)
    if match is None:
        raise EvidenceError(f"artifact must be path#sha256=<64 lowercase hex>: {ref!r}")
    rel = _safe_relative_path(match.group("path"))
    base = root.resolve(strict=True)
    candidate = base / rel
    # Do not follow symlinks, including a symlink in a parent directory.
    cursor = base
    for part in rel.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise EvidenceError(f"symlink artifact path: {rel}")
    try:
        path = candidate.resolve(strict=True)
        path.relative_to(base)
    except (OSError, ValueError) as exc:
        raise EvidenceError(f"artifact escapes root or is missing: {rel}") from exc
    if not path.is_file():
        raise EvidenceError(f"artifact is not a regular file: {rel}")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    got = digest.hexdigest()
    if got != match.group("digest"):
        raise EvidenceError(f"artifact digest mismatch: {rel}")
    return Artifact(ref, path, got)


def decimal_value(value: Any, label: str, *, nonnegative: bool = True) -> Decimal:
    if not isinstance(value, str) or not value.strip():
        raise EvidenceError(f"{label} must be a decimal string")
    if len(value.strip()) > 256:
        raise EvidenceError(f"{label} exceeds the exact-decimal input limit")
    try:
        number = Decimal(value)
    except InvalidOperation as exc:
        raise EvidenceError(f"{label} is not a decimal") from exc
    if not number.is_finite() or (nonnegative and number < 0):
        raise EvidenceError(f"{label} must be finite and nonnegative")
    if len(number.as_tuple().digits) > 256 or abs(number.as_tuple().exponent) > 256:
        raise EvidenceError(f"{label} exceeds the exact-decimal digit/exponent limit")
    return number


def _require_list(data: dict[str, Any], name: str) -> list[Any]:
    value = data.get(name)
    if not isinstance(value, list):
        raise EvidenceError(f"ledger.{name} must be an array")
    return value


def _priced_value(entry: Any, label: str, root: Path | None, *, terminal: bool = False) -> Decimal:
    if not isinstance(entry, dict):
        raise EvidenceError(f"{label} must be an object")
    if not isinstance(entry.get("asset"), str) or not entry["asset"].strip():
        raise EvidenceError(f"{label}.asset is required")
    if entry.get("price_basis") != "independent_executable":
        raise EvidenceError(f"{label}.price_basis must be independent_executable, not an internal/manipulated quote")
    if terminal and not str(entry.get("liquidity_assumption", "")).strip():
        raise EvidenceError(f"{label}.liquidity_assumption is required for terminal value")
    price_ref = entry.get("price_evidence")
    if root is not None:
        if not isinstance(price_ref, str):
            raise EvidenceError(f"{label}.price_evidence must be a hashed artifact reference")
        artifact_ref(price_ref, root)
    return decimal_value(entry.get("quantity"), f"{label}.quantity") * decimal_value(entry.get("price"), f"{label}.price")


def calculate_ledger(data: Any, root: Path | None = None) -> dict[str, str]:
    """Return exact net wealth change in one valuation unit.

    The measured group contains every attacker-controlled account. Contributions
    from outside the group are deducted, withdrawals to outside it are added back,
    and outstanding liabilities are valued at terminal executable prices. Only
    costs *not already reflected in balances* are deducted separately.
    """
    # Inputs are bounded to 256 digits/exponent by decimal_value. Even a large
    # ledger fits within 1024 digits after products and summation, so Decimal
    # never silently rounds a 256-bit balance or a scaled price.
    with localcontext() as context:
        context.prec = 1024
        return _calculate_ledger(data, root)


def _calculate_ledger(data: Any, root: Path | None) -> dict[str, str]:
    if not isinstance(data, dict):
        raise EvidenceError("ledger must be a JSON object")
    unit = data.get("valuation_unit")
    if not isinstance(unit, str) or not unit.strip():
        raise EvidenceError("ledger.valuation_unit is required")
    accounts = _require_list(data, "attacker_accounts")
    if not accounts or any(not isinstance(a, str) or not a.strip() for a in accounts) or len(set(accounts)) != len(accounts):
        raise EvidenceError("ledger.attacker_accounts must be unique nonempty strings")
    group = set(accounts)
    fields = (
        "initial_assets", "terminal_assets", "initial_liabilities", "terminal_liabilities",
        "capital_contributions", "capital_withdrawals", "off_balance_costs",
        "financing", "synthetic_setup", "market_assumptions",
    )
    for field in fields:
        _require_list(data, field)
    if not data["market_assumptions"] or any(not isinstance(x, str) or not x.strip() for x in data["market_assumptions"]):
        raise EvidenceError("ledger.market_assumptions must state executable price and liquidity assumptions")

    totals: dict[str, Decimal] = {}
    for field in ("initial_assets", "terminal_assets", "initial_liabilities", "terminal_liabilities",
                  "capital_contributions", "capital_withdrawals"):
        total = Decimal(0)
        for i, entry in enumerate(data[field]):
            label = f"ledger.{field}[{i}]"
            if not isinstance(entry, dict):
                raise EvidenceError(f"{label} must be an object")
            if field not in {"capital_contributions", "capital_withdrawals"} and entry.get("account") not in group:
                raise EvidenceError(f"{label}.account is outside attacker_accounts")
            total += _priced_value(entry, label, root, terminal=field.startswith("terminal_"))
        totals[field] = total

    costs = Decimal(0)
    for i, item in enumerate(data["off_balance_costs"]):
        label = f"ledger.off_balance_costs[{i}]"
        if not isinstance(item, dict) or item.get("not_in_balances") is not True or not str(item.get("label", "")).strip():
            raise EvidenceError(f"{label} must identify a cost not already reflected in balances")
        costs += decimal_value(item.get("amount"), f"{label}.amount")
    totals["off_balance_costs"] = costs

    outstanding_by_asset: dict[str, Decimal] = {}
    for i, item in enumerate(data["financing"]):
        label = f"ledger.financing[{i}]"
        if not isinstance(item, dict) or not isinstance(item.get("asset"), str) or not item["asset"].strip():
            raise EvidenceError(f"{label}.asset is required")
        borrowed = decimal_value(item.get("borrowed"), f"{label}.borrowed")
        repaid = decimal_value(item.get("repaid"), f"{label}.repaid")
        fee = decimal_value(item.get("fee"), f"{label}.fee")
        outstanding = decimal_value(item.get("outstanding"), f"{label}.outstanding")
        if borrowed + fee != repaid + outstanding:
            raise EvidenceError(f"{label} does not reconcile borrowed + fee = repaid + outstanding")
        outstanding_by_asset[item["asset"]] = outstanding_by_asset.get(item["asset"], Decimal(0)) + outstanding
    liability_by_asset: dict[str, Decimal] = {}
    for item in data["terminal_liabilities"]:
        liability_by_asset[item["asset"]] = liability_by_asset.get(item["asset"], Decimal(0)) + decimal_value(item["quantity"], "terminal liability quantity")
    for asset, outstanding in outstanding_by_asset.items():
        if liability_by_asset.get(asset, Decimal(0)) < outstanding:
            raise EvidenceError(f"outstanding financing in {asset} is missing from terminal_liabilities")

    initial_by_asset: dict[str, Decimal] = {}
    contribution_by_asset: dict[str, Decimal] = {}
    for item in data["initial_assets"]:
        initial_by_asset[item["asset"]] = initial_by_asset.get(item["asset"], Decimal(0)) + decimal_value(item["quantity"], "initial asset quantity")
    for item in data["capital_contributions"]:
        contribution_by_asset[item["asset"]] = contribution_by_asset.get(item["asset"], Decimal(0)) + decimal_value(item["quantity"], "contribution quantity")
    for i, item in enumerate(data["synthetic_setup"]):
        label = f"ledger.synthetic_setup[{i}]"
        if not isinstance(item, dict) or item.get("accounting") not in {"initial_balance", "external_contribution"}:
            raise EvidenceError(f"{label}.accounting must be initial_balance or external_contribution")
        if not isinstance(item.get("asset"), str) or not item["asset"].strip() or not str(item.get("real_world_source", "")).strip():
            raise EvidenceError(f"{label} must disclose asset and real-world capital source")
        quantity = decimal_value(item.get("quantity"), f"{label}.quantity")
        pool = initial_by_asset if item["accounting"] == "initial_balance" else contribution_by_asset
        if pool.get(item["asset"], Decimal(0)) < quantity:
            raise EvidenceError(f"{label} fixture funding was not deducted as capital")

    net = (
        totals["terminal_assets"] - totals["initial_assets"]
        - totals["terminal_liabilities"] + totals["initial_liabilities"]
        - totals["capital_contributions"] + totals["capital_withdrawals"]
        - costs
    )
    return {"valuation_unit": unit, "net_profit": format(net, "f"),
            **{name: format(value, "f") for name, value in totals.items()}}


def _validated_artifacts(refs: list[str], root: Path, errors: list[str], label: str) -> dict[str, Artifact]:
    out: dict[str, Artifact] = {}
    for i, ref in enumerate(refs):
        try:
            art = artifact_ref(ref, root)
            if art.ref in out:
                raise EvidenceError("duplicate artifact reference")
            out[art.ref] = art
        except (EvidenceError, OSError) as exc:
            errors.append(f"{label}[{i}]: {exc}")
    return out


def _ledger_price_refs(data: dict[str, Any]) -> set[str]:
    refs: set[str] = set()
    for field in ("initial_assets", "terminal_assets", "initial_liabilities", "terminal_liabilities",
                  "capital_contributions", "capital_withdrawals"):
        for entry in data[field]:
            ref = entry.get("price_evidence")
            if isinstance(ref, str):
                refs.add(ref)
    return refs


def _manifest_gate(record: dict[str, Any], artifacts: dict[str, Artifact], errors: list[str]) -> None:
    env = record["environment"]
    expected = env["environment_manifest_sha256"].lower()
    matches = [art for art in artifacts.values() if art.digest == expected]
    if len(matches) != 1:
        errors.append("exactly one hashed manifest artifact must match environment_manifest_sha256")
        return
    try:
        manifest = read_json(matches[0].path)
        if not isinstance(manifest, dict):
            raise EvidenceError("manifest must be a JSON object")
        details = manifest.get("environment", manifest)
        if not isinstance(details, dict) or details.get("code_identity") != env["code_identity"]:
            raise EvidenceError("manifest code_identity differs from finding environment")
        identity = env["code_identity"]
        if identity["kind"] in {"source_archive_sha256", "runtime_bytecode_sha256"}:
            if identity["digest"].lower() not in {art.digest for art in artifacts.values()}:
                raise EvidenceError("code identity digest has no matching retained source/bytecode artifact")
        for key in ("commit", "chain", "fork_block", "fork_block_hash", "compiler", "optimizer",
                    "evm_revision", "execution_engine", "tool_versions"):
            if key in details and key in env and details[key] != env[key]:
                raise EvidenceError(f"manifest {key} differs from finding environment")
        if not isinstance(details.get("tool_versions"), dict) or not details["tool_versions"]:
            raise EvidenceError("manifest must record nonempty tool_versions")
    except EvidenceError as exc:
        errors.append(str(exc))


def _receipt_gate(record: dict[str, Any], artifacts: dict[str, Artifact], errors: list[str],
                  *, independent: bool = False) -> None:
    ev = record["evidence"]
    env = record["environment"]
    if ev["kind"] in TEST_KINDS:
        required_kind = "independent_replay" if independent else "replay"
    else:
        required_kind = "proof_check"
    matches: list[dict[str, Any]] = []
    for art in artifacts.values():
        if art.path.suffix != ".json":
            continue
        try:
            receipt = read_json(art.path)
        except EvidenceError:
            continue
        if isinstance(receipt, dict) and receipt.get("kind") == required_kind:
            matches.append(receipt)
    if len(matches) != 1:
        errors.append(f"exactly one {required_kind} receipt artifact is required")
        return
    receipt = matches[0]
    expected = {
        "command": ev["command"],
        "test_id": ev["test_id"],
        "manifest_sha256": env["environment_manifest_sha256"],
        "exit_code": 0,
        "result": "pass",
    }
    for key, value in expected.items():
        if receipt.get(key) != value:
            errors.append(f"{required_kind} receipt {key} does not match finding")
    if independent:
        iv = ev["independent_verification"]
        if receipt.get("verifier") != iv["verifier"] or receipt.get("method") != iv["method"]:
            errors.append("independent receipt verifier/method does not match finding")
    log_ref = receipt.get("log_ref")
    if not isinstance(log_ref, str) or log_ref not in artifacts:
        errors.append(f"{required_kind} receipt must name a hashed log_ref listed among its artifacts")
    elif ev["kind"] in TEST_KINDS:
        log_path = artifacts[log_ref].path
        if log_path.stat().st_size > 64 * 1024 * 1024:
            errors.append(f"{required_kind} replay log exceeds 64 MiB")
        else:
            log = log_path.read_bytes()
            if b"[PASS]" not in log or b"0 failed" not in log or b"[FAIL]" in log:
                errors.append(f"{required_kind} replay log does not show a clean Forge test result")


def _deployment_binding_gate(record: dict[str, Any], artifacts: dict[str, Artifact],
                             root: Path, errors: list[str]) -> None:
    import deployment_bind

    matches = []
    for artifact in artifacts.values():
        if artifact.path.suffix != ".json":
            continue
        try:
            candidate = read_json(artifact.path)
        except EvidenceError:
            continue
        if isinstance(candidate, dict) and candidate.get("kind") == "exact_deployment_source_binding":
            matches.append(candidate)
    if len(matches) != 1:
        errors.append("verified source_bytecode_match requires exactly one deployment binding artifact")
        return
    binding = matches[0]
    for key in ("result_ref", "manifest_ref", "source_archive_ref", "snapshot_ref", "sourcify_response_ref"):
        ref = binding.get(key)
        if not isinstance(ref, str) or ref not in artifacts:
            errors.append(f"deployment binding {key} must be listed among evidence.artifacts")
    if errors:
        return
    try:
        summary = deployment_bind.verify_binding(root, binding)
    except (deployment_bind.BindingError, OSError, ValueError) as exc:
        errors.append(f"deployment binding: {exc}")
        return
    env = record["environment"]
    if (env.get("chain"), env.get("fork_block"), env.get("fork_block_hash")) != (
            str(summary["chain_id"]), summary["block_number"], summary["block_hash"]):
        errors.append("deployment binding chain/block differs from finding environment")
    if env.get("environment_manifest_sha256") != summary["run_manifest_sha256"]:
        errors.append("deployment binding run manifest differs from finding environment")
    if env.get("code_identity") != {"kind": "source_archive_sha256", "digest": summary["source_archive_sha256"]}:
        errors.append("deployment binding source archive differs from finding environment")


def validate_record(record: Any, root: Path, schema_path: Path = SCHEMA_PATH) -> tuple[list[str], dict[str, str] | None]:
    schema = read_json(schema_path)
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = [f"schema {'.'.join(map(str, err.absolute_path)) or '<root>'}: {err.message}"
              for err in sorted(validator.iter_errors(record), key=lambda e: (list(map(str, e.absolute_path)), e.message))]
    if errors:
        return errors, None
    if not root.is_dir():
        return [f"artifact root does not exist: {root}"], None
    ev = record["evidence"]
    artifacts = _validated_artifacts(ev["artifacts"], root, errors, "evidence.artifacts")
    ledger_result = None
    if record["environment"].get("source_bytecode_match") == "verified":
        _deployment_binding_gate(record, artifacts, root, errors)
    if record["status"] in CONFIRMABLE:
        if ev["kind"] == "fork_test":
            errors.append("fork_test promotion requires a fixed-block runner receipt; manual fork traces are exploratory")
        if ev["replayed_cleanly"] is not True:
            errors.append("reproduced/confirmed evidence requires a clean replay")
        if not ev["reachability_explanation"].strip():
            errors.append("reproduced/confirmed evidence requires reachability")
        if not isinstance(ev.get("before_state"), dict) or not ev["before_state"]:
            errors.append("reproduced/confirmed evidence requires a measured before_state")
        if not isinstance(ev.get("after_state"), dict) or not ev["after_state"]:
            errors.append("reproduced/confirmed evidence requires a measured after_state")
        if record["impact"]["category"] in {"unknown", "not_applicable", "no_confirmed_impact"}:
            errors.append("reproduced/confirmed evidence requires a concrete impact category")
        if not record["false_positive_review"]:
            errors.append("reproduced/confirmed evidence requires at least one negative-control or counterevidence review")
        _manifest_gate(record, artifacts, errors)
        _receipt_gate(record, artifacts, errors)
        if record["status"] == "confirmed":
            iv = ev["independent_verification"]
            separate = _validated_artifacts(iv["artifacts"], root, errors, "independent_verification.artifacts")
            if set(separate) & set(artifacts):
                errors.append("independent verification must use separate artifacts")
            _receipt_gate(record, separate, errors, independent=True)
    elif record["impact"]["profit_claimed"]:
        errors.append("profit_claimed is reserved for reproduced or confirmed evidence")
    if record["impact"]["profit_claimed"]:
        model = record["impact"].get("profit_model")
        if not isinstance(model, str) or not model.startswith("ledger:"):
            errors.append("profit claims require impact.profit_model='ledger:<hashed artifact ref>'")
        else:
            ref = model.removeprefix("ledger:")
            if ref not in artifacts:
                errors.append("economic ledger must be listed among evidence.artifacts")
            else:
                try:
                    ledger_data = read_json(artifacts[ref].path)
                    ledger_result = calculate_ledger(ledger_data, root)
                    missing_prices = _ledger_price_refs(ledger_data) - set(artifacts)
                    if missing_prices:
                        errors.append("price evidence used by the ledger must be listed among evidence.artifacts")
                    if Decimal(ledger_result["net_profit"]) <= 0:
                        errors.append("profit_claimed requires positive net profit after full ledger costs")
                except EvidenceError as exc:
                    errors.append(f"economic ledger: {exc}")
    return errors, ledger_result


def record_from_run(result_path: Path, details: dict[str, Any] | None = None,
                    status: str = "hypothesis") -> dict[str, Any]:
    """Create a draft from a bounded runner result without inventing a finding.

    A passing Forge test does not explain attacker control or demonstrate an
    exploit. Promotion to ``reproduced`` is explicit and requires human/agent
    supplied semantic details; ``confirmed`` is never generated here.
    """
    if status not in {"hypothesis", "reproduced"}:
        raise EvidenceError("from-run creates only hypothesis or reproduced drafts")
    result = read_json(result_path)
    if not isinstance(result, dict) or not isinstance(result.get("manifest"), str):
        raise EvidenceError("runner result must include its manifest path")
    root = result_path.resolve().parent
    manifest_path = Path(result["manifest"]).resolve()
    try:
        manifest_path.relative_to(root)
    except ValueError as exc:
        raise EvidenceError("runner manifest must be inside the result directory") from exc
    manifest = read_json(manifest_path)
    if not isinstance(manifest, dict) or not isinstance(manifest.get("environment"), dict):
        raise EvidenceError("runner manifest lacks environment")
    env = manifest["environment"]
    manifest_sha = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    if result.get("manifest_sha256") != manifest_sha:
        raise EvidenceError("runner result manifest hash does not match retained manifest")
    refs = result.get("evidence_artifact_refs")
    if not isinstance(refs, list) or not all(isinstance(ref, str) for ref in refs):
        raise EvidenceError("runner result lacks hashed evidence_artifact_refs")
    for ref in refs:
        artifact_ref(ref, root)
    deployment = None
    binding_path = root / "deployment_binding.json"
    if binding_path.is_file():
        import deployment_bind

        binding = read_json(binding_path)
        try:
            deployment = deployment_bind.verify_binding(root, binding)
        except (deployment_bind.BindingError, OSError, ValueError) as exc:
            raise EvidenceError(f"deployment binding is invalid: {exc}") from exc
        refs = list(dict.fromkeys(refs + [
            "deployment_binding.json#sha256=" + hashlib.sha256(binding_path.read_bytes()).hexdigest(),
            binding["result_ref"], binding["snapshot_ref"], binding["sourcify_response_ref"],
        ]))
    details = details or {}
    if not isinstance(details, dict):
        raise EvidenceError("semantic details must be a JSON object")
    if status == "reproduced":
        if result.get("action") != "forge-test" or result.get("status") != "pass" or not result.get("replay_receipt"):
            raise EvidenceError("reproduced draft requires a passing forge-test replay receipt")
        for key in ("id", "title", "detector_ids", "root_cause", "attacker_capabilities",
                    "preconditions", "locations", "violated_property", "reachability_explanation",
                    "before_state", "after_state", "false_positive_review"):
            value = details.get(key)
            if not value or (isinstance(value, str) and not value.strip()):
                raise EvidenceError(f"reproduced draft requires supplied {key}")
        if not isinstance(details.get("impact"), dict) or not str(details["impact"].get("description", "")).strip():
            raise EvidenceError("reproduced draft requires supplied impact with description")
    finding_env = {
        "commit": env.get("commit"),
        "chain": env.get("chain"),
        "fork_block": env.get("fork_block"),
        "compiler": env.get("compiler"),
        "tool_versions": env.get("tool_versions", {}),
        "code_identity": env.get("code_identity"),
        "execution_engine": env.get("execution_engine"),
        "environment_manifest_sha256": manifest_sha,
        "source_bytecode_match": env.get("source_bytecode_match", "unverified" if env.get("chain") else "not_applicable"),
    }
    if deployment is not None:
        finding_env["source_bytecode_match"] = "verified"
        finding_env["fork_block_hash"] = deployment["block_hash"]
    for key in ("optimizer", "evm_revision", "fork_block_hash"):
        if key in env:
            finding_env[key] = env[key]
    if status == "hypothesis":
        kind = "static_trace" if result.get("action") == "slither" else "none"
        evidence = {"kind": kind, "test_id": None, "replayed_cleanly": False,
                    "artifacts": refs, "reachability_explanation": "",
                    "command": result.get("command") or None}
    else:
        evidence = {"kind": "local_test", "test_id": result.get("test_id"),
                    "replayed_cleanly": True, "artifacts": refs,
                    "reachability_explanation": details["reachability_explanation"],
                    "command": result.get("command"), "seed": None,
                    "before_state": details["before_state"], "after_state": details["after_state"]}
    record = {
        "id": details.get("id", "draft-from-run"),
        "title": details.get("title", "Unreviewed analysis result"),
        "status": status,
        "severity": details.get("severity", "unrated"),
        "detector_ids": details.get("detector_ids", ["manual.unclassified"]),
        "environment": finding_env,
        "root_cause": details.get("root_cause", ""),
        "attacker_capabilities": details.get("attacker_capabilities", []),
        "preconditions": details.get("preconditions", []),
        "locations": details.get("locations", []),
        "violated_property": details.get("violated_property", ""),
        "evidence": evidence,
        "impact": details.get("impact", {"category": "unknown", "description": "", "profit_claimed": False}),
        "false_positive_review": details.get("false_positive_review", []),
        "limitations": details.get("limitations", ["Generated draft; semantic reachability and impact remain unreviewed."]),
    }
    errors, _ = validate_record(record, root)
    if errors:
        raise EvidenceError("draft failed validation: " + "; ".join(errors))
    return record


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    validate = sub.add_parser("validate", help="validate schema and evidence promotion gates")
    validate.add_argument("record", type=Path)
    validate.add_argument("--artifact-root", type=Path, required=True)
    validate.add_argument("--schema", type=Path, default=SCHEMA_PATH)
    ledger = sub.add_parser("ledger", help="calculate an exact economic ledger")
    ledger.add_argument("ledger", type=Path)
    ledger.add_argument("--artifact-root", type=Path)
    from_run = sub.add_parser("from-run", help="draft a hypothesis or explicit reproduced record from runner artifacts")
    from_run.add_argument("result", type=Path)
    from_run.add_argument("--details", type=Path, help="JSON with human/agent supplied root cause and impact details")
    from_run.add_argument("--status", choices=("hypothesis", "reproduced"), default="hypothesis")
    from_run.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.action == "validate":
            errors, result = validate_record(read_json(args.record), args.artifact_root, args.schema)
            print(json.dumps({"ok": not errors, "errors": errors, "ledger": result}, indent=2))
            return 0 if not errors else 1
        if args.action == "from-run":
            details = read_json(args.details) if args.details else None
            record = record_from_run(args.result, details, args.status)
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(record, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
            print(json.dumps({"status": record["status"], "record": str(args.output)}))
            return 0
        print(json.dumps(calculate_ledger(read_json(args.ledger), args.artifact_root), indent=2))
        return 0
    except (EvidenceError, OSError, ValueError) as exc:
        print(json.dumps({"ok": False, "errors": [str(exc)]}, indent=2), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
