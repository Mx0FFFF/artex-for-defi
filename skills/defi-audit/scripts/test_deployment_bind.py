"""Exact source-to-runtime binding tests using synthetic local artifacts."""

from __future__ import annotations

import copy
import hashlib
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

import deployment_bind as binding
import evidence


ADDRESS = "0x" + "a1" * 20
BLOCK_HASH = "0x" + "ab" * 32
CODE = bytes.fromhex("6001600055")
SOURCE = "pragma solidity ^0.8.35; contract Vault {}\n"


def write_json(path: Path, value: dict) -> str:
    blob = (json.dumps(value, sort_keys=True) + "\n").encode()
    path.write_bytes(blob)
    return hashlib.sha256(blob).hexdigest()


class DeploymentBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.run = self.root / "run"
        self.run.mkdir()
        self.archive = self.run / "source_snapshot.tar"
        with tarfile.open(self.archive, "w") as tar:
            content = SOURCE.encode()
            info = tarfile.TarInfo("contracts/Vault.sol")
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
        archive_hash = binding.file_hash(self.archive, binding.MAX_ARCHIVE)
        manifest = {
            "environment": {
                "code_identity": {"kind": "source_archive_sha256", "digest": archive_hash},
                "commit": "a" * 40, "chain": "1", "fork_block": 100,
                "compiler": "Solc 0.8.35", "execution_engine": "Foundry 1.7.1",
                "tool_versions": {"forge": "1.7.1"},
            },
            "target_context": {"chain_id": 1, "block_number": 100, "address": ADDRESS},
            "source_snapshot": {"path": "source_snapshot.tar", "sha256": archive_hash},
        }
        manifest_hash = write_json(self.run / "manifest.json", manifest)
        stdout = self.run / "stdout.log"
        stdout.write_bytes(b"[PASS] test_Repro()\nSuite result: ok. 1 passed; 0 failed\n")
        stdout_ref = "stdout.log#sha256=" + binding.file_hash(stdout, 2 << 20)
        replay = self.run / "replay_receipt.json"
        replay_hash = write_json(replay, {
            "kind": "replay", "command": "forge test --match-test test_Repro",
            "test_id": "test_Repro", "manifest_sha256": manifest_hash,
            "exit_code": 0, "result": "pass", "log_ref": stdout_ref,
        })
        result = {
            "action": "forge-test", "status": "pass", "exit_code": 0,
            "source_drift": False, "manifest": str(self.run / "manifest.json"),
            "manifest_sha256": manifest_hash, "command": "forge test --match-test test_Repro",
            "test_id": "test_Repro", "replay_receipt": str(replay),
            "evidence_artifact_refs": [
                "source_snapshot.tar#sha256=" + archive_hash,
                "manifest.json#sha256=" + manifest_hash,
                stdout_ref,
                "replay_receipt.json#sha256=" + replay_hash,
            ],
        }
        write_json(self.run / "result.json", result)
        self.snapshot = self.root / "deployment.json"
        write_json(self.snapshot, {
            "kind": "read_only_deployment_snapshot", "schema_version": "1.0",
            "chain_id": 1, "block_number": 100, "block_hash": BLOCK_HASH,
            "addresses": [{"address": ADDRESS, "code_bytes": len(CODE),
                           "code_sha256": hashlib.sha256(CODE).hexdigest(), "code_empty": False}],
        })
        self.response = self.root / "sourcify-response.json"
        write_json(self.response, {
            "chainId": "1", "address": ADDRESS, "runtimeMatch": "exact_match",
            "runtimeBytecode": {"onchainBytecode": "0x" + CODE.hex()},
            "sources": {"contracts/Vault.sol": {"content": SOURCE}},
        })

    def test_exact_binding_promotes_source_correspondence(self) -> None:
        path = self.run / "deployment_binding.json"
        attached = binding.bind(self.run / "result.json", self.snapshot, self.response, path)
        summary = binding.verify_binding(self.run, attached)
        self.assertEqual(summary["runtime_code_sha256"], hashlib.sha256(CODE).hexdigest())
        record = evidence.record_from_run(self.run / "result.json")
        self.assertEqual(record["environment"]["source_bytecode_match"], "verified")
        self.assertEqual(record["environment"]["fork_block_hash"], BLOCK_HASH)
        errors, _ = evidence.validate_record(record, self.run)
        self.assertEqual(errors, [])
        details = {
            "id": "SYNTH-DEPLOYMENT", "title": "Synthetic source-bound defect",
            "severity": "medium", "detector_ids": ["synthetic.test"],
            "root_cause": "Synthetic branch", "attacker_capabilities": ["call public function"],
            "preconditions": ["synthetic pinned state"], "locations": ["contracts/Vault.sol:1"],
            "violated_property": "synthetic invariant", "reachability_explanation": "fixture reaches the branch",
            "before_state": {"balance": "10"}, "after_state": {"balance": "9"},
            "false_positive_review": ["control does not change balance"],
            "impact": {"category": "asset_loss", "description": "Synthetic unit loss", "profit_claimed": False},
        }
        reproduced = evidence.record_from_run(self.run / "result.json", details, "reproduced")
        errors, _ = evidence.validate_record(reproduced, self.run)
        self.assertEqual(errors, [])
        record["environment"]["fork_block_hash"] = "0x" + "00" * 32
        errors, _ = evidence.validate_record(record, self.run)
        self.assertTrue(any("deployment binding chain/block" in error for error in errors))

    def test_mismatch_and_partial_match_are_blocked(self) -> None:
        response = json.loads(self.response.read_text())
        response["runtimeMatch"] = "match"
        write_json(self.response, response)
        with self.assertRaisesRegex(binding.BindingError, "not exact"):
            binding.verify_inputs(self.run / "result.json", self.snapshot, self.response)
        response["runtimeMatch"] = "exact_match"
        response["runtimeBytecode"]["onchainBytecode"] = "0x6000"
        write_json(self.response, response)
        with self.assertRaisesRegex(binding.BindingError, "differ from pinned"):
            binding.verify_inputs(self.run / "result.json", self.snapshot, self.response)
        response["runtimeBytecode"]["onchainBytecode"] = "0x" + CODE.hex()
        response["sources"]["contracts/Vault.sol"]["content"] = SOURCE.replace("Vault", "Vaulx")
        write_json(self.response, response)
        with self.assertRaisesRegex(binding.BindingError, "differs from test snapshot"):
            binding.verify_inputs(self.run / "result.json", self.snapshot, self.response)

    def test_tampered_binding_artifact_is_rejected(self) -> None:
        path = self.run / "deployment_binding.json"
        attached = binding.bind(self.run / "result.json", self.snapshot, self.response, path)
        altered = copy.deepcopy(attached)
        altered["block_number"] = 101
        with self.assertRaisesRegex(binding.BindingError, "block_number differs"):
            binding.verify_binding(self.run, altered)


if __name__ == "__main__":
    unittest.main()
