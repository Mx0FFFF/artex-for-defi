"""Synthetic evidence fixtures; these tests do not assert a real exploit."""

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from evidence import EvidenceError, artifact_ref, calculate_ledger, record_from_run, validate_record


def put(root: Path, name: str, value) -> str:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    blob = json.dumps(value, sort_keys=True).encode() if not isinstance(value, bytes) else value
    path.write_bytes(blob)
    return f"{name}#sha256={hashlib.sha256(blob).hexdigest()}"


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        identity = {"kind": "git_commit", "digest": "a" * 40}
        versions = {"forge": "1.7.1"}
        manifest = {
            "environment": {
                "code_identity": identity,
                "commit": "a" * 40,
                "chain": None,
                "fork_block": None,
                "compiler": "0.8.35",
                "execution_engine": "foundry",
                "tool_versions": versions,
                "dependencies": {"example": "pinned"},
            }
        }
        manifest_ref = put(self.root, "manifest.json", manifest)
        manifest_hash = manifest_ref.rsplit("=", 1)[1]
        self.command = "forge test --match-test test_Repro"
        log_ref = put(self.root, "logs/replay.log", b"Ran 1 test\n[PASS] test_Repro\nSuite result: ok. 1 passed; 0 failed\n")
        replay = {
            "kind": "replay", "command": self.command, "test_id": "test_Repro",
            "manifest_sha256": manifest_hash, "exit_code": 0, "result": "pass",
            "log_ref": log_ref,
        }
        replay_ref = put(self.root, "replay.json", replay)
        self.record = {
            "id": "SYNTH-1", "title": "Synthetic accounting defect", "status": "reproduced",
            "severity": "medium", "detector_ids": ["synthetic.test"],
            "environment": {
                "commit": "a" * 40, "chain": None, "fork_block": None,
                "compiler": "0.8.35", "tool_versions": versions,
                "source_bytecode_match": "not_applicable",
                "code_identity": identity, "execution_engine": "foundry",
                "environment_manifest_sha256": manifest_hash,
            },
            "root_cause": "Synthetic arithmetic branch", "attacker_capabilities": ["call public function"],
            "preconditions": ["synthetic local state"], "locations": ["src/Vault.sol:42"],
            "violated_property": "claims must remain backed",
            "evidence": {
                "kind": "local_test", "test_id": "test_Repro", "replayed_cleanly": True,
                "artifacts": [manifest_ref, log_ref, replay_ref],
                "reachability_explanation": "The public call reaches the branch in the synthetic fixture.",
                "command": self.command, "seed": None,
                "before_state": {"victim_balance": "100"},
                "after_state": {"victim_balance": "90"},
            },
            "impact": {"category": "asset_loss", "description": "Synthetic balance delta", "profit_claimed": False},
            "false_positive_review": ["Negative control has no attacker-controlled call"],
            "limitations": ["Synthetic fixture; no production claim"],
        }

    def test_reproduced_and_confirmed_gates(self):
        errors, _ = validate_record(self.record, self.root)
        self.assertEqual(errors, [])
        confirmed = copy.deepcopy(self.record)
        confirmed["status"] = "confirmed"
        confirmed["false_positive_review"] = ["Independent replay removed the attacker input and no loss occurred."]
        independent_log = put(self.root, "logs/independent.log", b"[PASS] test_Repro independent\nSuite result: ok. 1 passed; 0 failed\n")
        independent_receipt = put(self.root, "independent.json", {
            "kind": "independent_replay", "command": self.command, "test_id": "test_Repro",
            "manifest_sha256": confirmed["environment"]["environment_manifest_sha256"],
            "exit_code": 0, "result": "pass", "log_ref": independent_log,
            "verifier": "separate-reviewer", "method": "independent_replay",
        })
        confirmed["evidence"]["independent_verification"] = {
            "performed": True, "method": "independent_replay", "verifier": "separate-reviewer",
            "artifacts": [independent_log, independent_receipt],
        }
        errors, _ = validate_record(confirmed, self.root)
        self.assertEqual(errors, [])
        confirmed["evidence"]["independent_verification"]["verifier"] = "invented-reviewer"
        errors, _ = validate_record(confirmed, self.root)
        self.assertTrue(any("verifier/method" in error for error in errors))

    def test_schema_and_replay_failures(self):
        record = copy.deepcopy(self.record)
        record["unexpected"] = 1
        errors, _ = validate_record(record, self.root)
        self.assertTrue(any("Additional properties" in error for error in errors))
        record = copy.deepcopy(self.record)
        record["evidence"]["artifacts"] = record["evidence"]["artifacts"][:-1]
        errors, _ = validate_record(record, self.root)
        self.assertTrue(any("replay receipt" in error for error in errors))
        record = copy.deepcopy(self.record)
        record["evidence"]["replayed_cleanly"] = False
        errors, _ = validate_record(record, self.root)
        self.assertTrue(any("replayed_cleanly" in error for error in errors))
        record = copy.deepcopy(self.record)
        record["evidence"]["command"] = "forge test --match-test different"
        errors, _ = validate_record(record, self.root)
        self.assertTrue(any("receipt command" in error for error in errors))
        record = copy.deepcopy(self.record)
        bad_log = put(self.root, "logs/bad.log", b"[PASS] one\n[FAIL] another\n1 passed; 1 failed\n")
        bad_receipt = put(self.root, "bad_replay.json", {
            "kind": "replay", "command": self.command, "test_id": "test_Repro",
            "manifest_sha256": self.record["environment"]["environment_manifest_sha256"],
            "exit_code": 0, "result": "pass", "log_ref": bad_log,
        })
        record["evidence"]["artifacts"] = record["evidence"]["artifacts"][:1] + [bad_log, bad_receipt]
        errors, _ = validate_record(record, self.root)
        self.assertTrue(any("clean Forge" in error for error in errors))
        record = copy.deepcopy(self.record)
        record["status"] = "hypothesis"
        record["impact"]["profit_claimed"] = True
        record["impact"]["profit_model"] = "unverified"
        errors, _ = validate_record(record, self.root)
        self.assertTrue(any("reserved for reproduced" in error for error in errors))

    def test_unbacked_deployment_match_is_rejected(self):
        record = copy.deepcopy(self.record)
        record["environment"]["source_bytecode_match"] = "verified"
        errors, _ = validate_record(record, self.root)
        self.assertTrue(any("deployment binding artifact" in error for error in errors))

    def test_manual_fork_cannot_be_promoted(self):
        record = copy.deepcopy(self.record)
        record["evidence"]["kind"] = "fork_test"
        record["environment"]["chain"] = "1"
        record["environment"]["fork_block"] = 100
        record["environment"]["fork_block_hash"] = "0x" + "ab" * 32
        errors, _ = validate_record(record, self.root)
        self.assertTrue(any("fixed-block runner receipt" in error for error in errors))

    def test_artifact_path_and_hash_rejected(self):
        path = self.root / "inside.txt"
        path.write_text("inside")
        digest = hashlib.sha256(b"inside").hexdigest()
        for ref in (f"../outside#sha256={digest}", f"/tmp/x#sha256={digest}", f"inside.txt#sha256={'0' * 64}"):
            with self.assertRaises(EvidenceError):
                artifact_ref(ref, self.root)
        (self.root / "link.txt").symlink_to(path)
        with self.assertRaises(EvidenceError):
            artifact_ref(f"link.txt#sha256={digest}", self.root)

    def _ledger(self):
        price_ref = put(self.root, "prices/independent.json", {"asset": "USD", "bid": "1", "depth": "100000"})
        asset = lambda quantity, terminal=False: {
            "account": "attacker-a", "asset": "USD", "quantity": quantity, "price": "1",
            "price_basis": "independent_executable", "price_evidence": price_ref,
            **({"liquidity_assumption": "Can sell all USD at 1 within observed depth"} if terminal else {}),
        }
        return {
            "valuation_unit": "USD", "attacker_accounts": ["attacker-a", "attacker-b"],
            "initial_assets": [asset("100")], "terminal_assets": [asset("120", True)],
            "initial_liabilities": [], "terminal_liabilities": [],
            "capital_contributions": [], "capital_withdrawals": [],
            "off_balance_costs": [{"label": "gas outside measured accounts", "amount": "2", "not_in_balances": True}],
            "financing": [{"asset": "USD", "borrowed": "50", "repaid": "51", "fee": "1", "outstanding": "0"}],
            "synthetic_setup": [{"asset": "USD", "quantity": "100", "accounting": "initial_balance",
                                 "real_world_source": "Requires 100 USD independent starting capital"}],
            "market_assumptions": ["Independent executable price and sufficient terminal market depth"],
        }

    def test_exact_ledger_and_profit_gate(self):
        ledger = self._ledger()
        result = calculate_ledger(ledger, self.root)
        self.assertEqual(result["net_profit"], "18")
        ref = put(self.root, "economics/ledger.json", ledger)
        record = copy.deepcopy(self.record)
        record["evidence"]["artifacts"].append(ref)
        record["evidence"]["artifacts"].append(ledger["initial_assets"][0]["price_evidence"])
        record["impact"]["profit_claimed"] = True
        record["impact"]["profit_model"] = "ledger:" + ref
        errors, output = validate_record(record, self.root)
        self.assertEqual(errors, [])
        self.assertEqual(output["net_profit"], "18")
        record["evidence"]["artifacts"].pop()
        errors, _ = validate_record(record, self.root)
        self.assertTrue(any("price evidence" in error for error in errors))
        ledger["terminal_assets"][0]["price_basis"] = "manipulated_oracle_quote"
        with self.assertRaises(EvidenceError):
            calculate_ledger(ledger, self.root)

    def test_large_integer_ledger_stays_exact(self):
        ledger = self._ledger()
        initial = "1" + "0" * 78
        ledger["initial_assets"][0]["quantity"] = initial
        ledger["terminal_assets"][0]["quantity"] = str(int(initial) + 1)
        ledger["synthetic_setup"][0]["quantity"] = initial
        ledger["off_balance_costs"][0]["amount"] = "0"
        self.assertEqual(calculate_ledger(ledger, self.root)["net_profit"], "1")

    def test_from_run_requires_semantics_for_reproduction(self):
        refs = self.record["evidence"]["artifacts"]
        result = {
            "manifest": str(self.root / "manifest.json"),
            "manifest_sha256": self.record["environment"]["environment_manifest_sha256"],
            "evidence_artifact_refs": refs,
            "action": "forge-test", "status": "pass",
            "replay_receipt": str(self.root / "replay.json"),
            "command": self.command, "test_id": "test_Repro",
        }
        put(self.root, "result.json", result)
        draft = record_from_run(self.root / "result.json")
        self.assertEqual(draft["status"], "hypothesis")
        self.assertFalse(draft["evidence"]["replayed_cleanly"])
        with self.assertRaises(EvidenceError):
            record_from_run(self.root / "result.json", status="reproduced")
        supplied = {
            key: self.record[key] for key in
            ("id", "title", "detector_ids", "root_cause", "attacker_capabilities",
             "preconditions", "locations", "violated_property", "impact", "false_positive_review")
        }
        supplied["reachability_explanation"] = self.record["evidence"]["reachability_explanation"]
        supplied["before_state"] = self.record["evidence"]["before_state"]
        supplied["after_state"] = self.record["evidence"]["after_state"]
        reproduced = record_from_run(self.root / "result.json", supplied, "reproduced")
        self.assertEqual(reproduced["status"], "reproduced")
        self.assertEqual(validate_record(reproduced, self.root)[0], [])
        with self.assertRaises(EvidenceError):
            record_from_run(self.root / "result.json", supplied, "confirmed")

    def test_formal_result_requires_checkable_receipt(self):
        record = copy.deepcopy(self.record)
        record["evidence"]["kind"] = "proof"
        record["evidence"]["test_id"] = None
        record["evidence"]["command"] = "check-proof proof.bundle"
        record["evidence"]["proof_scope"] = "For all uint256 deposits under the stated contract model"
        log_ref = self.record["evidence"]["artifacts"][1]
        proof_receipt = put(self.root, "proof_check.json", {
            "kind": "proof_check", "command": "check-proof proof.bundle", "test_id": None,
            "manifest_sha256": record["environment"]["environment_manifest_sha256"],
            "exit_code": 0, "result": "pass", "log_ref": log_ref,
        })
        record["evidence"]["artifacts"].append(proof_receipt)
        self.assertEqual(validate_record(record, self.root)[0], [])

    def test_fixture_funding_and_outstanding_debt_cannot_be_profit(self):
        ledger = self._ledger()
        ledger["synthetic_setup"][0]["quantity"] = "1000"
        with self.assertRaises(EvidenceError):
            calculate_ledger(ledger, self.root)
        ledger = self._ledger()
        ledger["financing"][0]["repaid"] = "0"
        ledger["financing"][0]["outstanding"] = "51"
        with self.assertRaises(EvidenceError):
            calculate_ledger(ledger, self.root)
        ledger["terminal_liabilities"].append({
            "account": "attacker-a", "asset": "USD", "quantity": "51", "price": "1",
            "price_basis": "independent_executable", "price_evidence": ledger["initial_assets"][0]["price_evidence"],
            "liquidity_assumption": "Debt is repayable at par",
        })
        self.assertEqual(calculate_ledger(ledger, self.root)["net_profit"], "-33")


if __name__ == "__main__":
    unittest.main()
