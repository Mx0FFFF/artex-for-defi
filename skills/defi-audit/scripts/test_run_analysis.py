#!/usr/bin/env python3
"""Safety and evidence tests for the local DeFi analysis wrapper."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("run_analysis.py")


class RunAnalysisTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.project = self.root / "project"
        self.project.mkdir()
        (self.project / "src").mkdir()
        (self.project / "src" / "Vault.sol").write_text("pragma solidity ^0.8.20; contract Vault {}\n")
        (self.project / "foundry.toml").write_text(
            '[profile.default]\nsolc_version = "0.8.20"\noptimizer = true\n'
            '[rpc_endpoints]\nmainnet = "https://user:private-token@example.org"\n'
        )
        self.output = self.project / ".artex-defi-analysis"
        self.bin_dir = self.root / "bin"
        self.bin_dir.mkdir()
        self.env = dict(os.environ)
        self.env["PATH"] = str(self.bin_dir) + os.pathsep + self.env.get("PATH", "")

    def mock_tool(self, name: str, body: str, *, config_ffi: bool = False) -> None:
        path = self.bin_dir / name
        prefix = "#!/usr/bin/env python3\nimport sys, time, json\n"
        if name == "forge":
            prefix += 'if "config" in sys.argv:\n    print(json.dumps({"ffi": ' + repr(config_ffi) + '}))\n    sys.exit(0)\n'
        path.write_text(prefix + textwrap.dedent(body))
        path.chmod(0o755)

    def run_cli(self, command: str, *extras: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(SCRIPT), command, "--project", str(self.project),
             "--output-dir", str(self.output), *extras],
            text=True, capture_output=True, env=self.env, timeout=20,
        )

    def result(self, completed: subprocess.CompletedProcess) -> tuple[dict, Path]:
        summary = json.loads(completed.stdout)
        result_path = Path(summary["result"])
        return json.loads(result_path.read_text()), result_path.parent

    def test_manifest_has_stable_tree_hash_and_no_rpc_secret(self) -> None:
        self.mock_tool("forge", 'print("forge mock 1.0")\n')
        first = self.run_cli("manifest", "--chain-id", "1", "--block-number", "123")
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(json.loads(first.stdout)["environment_manifest_sha256"], hashlib.sha256((self.output / "manifest.json").read_bytes()).hexdigest())
        manifest = json.loads((self.output / "manifest.json").read_text())
        self.assertEqual(manifest["environment"]["code_identity"]["kind"], "source_archive_sha256")
        self.assertEqual(manifest["environment"]["code_identity"]["digest"], hashlib.sha256((self.output / "source_snapshot.tar").read_bytes()).hexdigest())
        self.assertEqual(manifest["target_context"]["block_number"], 123)
        self.assertEqual(manifest["environment"]["tool_versions"]["forge"], "forge mock 1.0")
        self.assertNotIn("private-token", json.dumps(manifest))
        original = manifest["source_tree_sha256"]
        archive_hash = hashlib.sha256((self.output / "source_snapshot.tar").read_bytes()).hexdigest()
        second = self.run_cli("manifest", "--chain-id", "1", "--block-number", "123")
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(json.loads((self.output / "manifest.json").read_text())["source_tree_sha256"], original)
        self.assertEqual(hashlib.sha256((self.output / "source_snapshot.tar").read_bytes()).hexdigest(), archive_hash)
        (self.project / "src" / "Vault.sol").write_text("pragma solidity ^0.8.20; contract Vault { uint x; }\n")
        third = self.run_cli("manifest")
        self.assertEqual(third.returncode, 0, third.stderr)
        self.assertNotEqual(json.loads((self.output / "manifest.json").read_text())["source_tree_sha256"], original)

    def test_passing_forge_test_emits_hashed_replay_receipt(self) -> None:
        self.mock_tool("forge", '''
if "--version" in sys.argv:
    print("forge mock 1.0")
elif "test" in sys.argv:
    print("Ran 1 test for test/Vault.t.sol:VaultTest")
    print("[PASS] testSolvency()")
''')
        completed = self.run_cli("run", "forge-test", "--match-contract", "VaultTest", "--match-test", "testSolvency")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        result, run_dir = self.result(completed)
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["test_id"], "VaultTest::testSolvency")
        receipt = json.loads((run_dir / "replay_receipt.json").read_text())
        self.assertEqual(receipt["kind"], "replay")
        self.assertEqual(receipt["command"], result["command"])
        self.assertEqual(receipt["test_id"], result["test_id"])
        self.assertEqual(receipt["manifest_sha256"], result["manifest_sha256"])
        log_hash = hashlib.sha256((run_dir / "stdout.log").read_bytes()).hexdigest()
        self.assertEqual(receipt["log_ref"], "stdout.log#sha256=" + log_hash)
        self.assertIn(receipt["log_ref"], result["evidence_artifact_refs"])
        self.assertTrue(any(ref.startswith("replay_receipt.json#sha256=") for ref in result["evidence_artifact_refs"]))

    def test_failing_or_empty_forge_test_is_incomplete(self) -> None:
        self.mock_tool("forge", '''
if "--version" in sys.argv:
    print("forge mock 1.0")
elif "test" in sys.argv:
    print("[FAIL] testSolvency()")
    sys.exit(1)
''')
        completed = self.run_cli("run", "forge-test")
        self.assertEqual(completed.returncode, 2)
        result, _ = self.result(completed)
        self.assertEqual(result["status"], "incomplete")
        self.assertIsNone(result["replay_receipt"])
        self.mock_tool("forge", '''
if "--version" in sys.argv:
    print("forge mock 1.0")
else:
    print("No tests found")
''')
        completed = self.run_cli("run", "forge-test")
        self.assertEqual(completed.returncode, 2)
        result, _ = self.result(completed)
        self.assertEqual(result["status_reason"], "forge test did not report a passing test")

    def test_slither_candidate_findings_even_with_detector_exit_code(self) -> None:
        self.mock_tool("slither", '''
if "--version" in sys.argv:
    print("slither mock 1.0")
else:
    print(json.dumps({"success": True, "results": {"detectors": [{"check": "reentrancy"}]}}))
    sys.exit(255)
''')
        completed = self.run_cli("run", "slither")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        result, _ = self.result(completed)
        self.assertEqual(result["status"], "findings")
        self.assertEqual(result["candidate_count"], 1)
        self.assertEqual(result["exit_code"], 255)

    def test_timeout_and_output_limit_are_incomplete(self) -> None:
        self.mock_tool("forge", '''
if "--version" in sys.argv:
    print("forge mock 1.0")
else:
    time.sleep(3)
''')
        completed = self.run_cli("run", "forge-build", "--timeout", "1")
        self.assertEqual(completed.returncode, 2)
        result, _ = self.result(completed)
        self.assertTrue(result["timed_out"])
        self.assertEqual(result["status"], "incomplete")
        self.mock_tool("forge", '''
if "--version" in sys.argv:
    print("forge mock 1.0")
else:
    print("X" * 4096)
''')
        completed = self.run_cli("run", "forge-build", "--max-output-bytes", "128")
        self.assertEqual(completed.returncode, 2)
        result, run_dir = self.result(completed)
        self.assertTrue(result["output_limited"])
        self.assertLessEqual((run_dir / "stdout.log").stat().st_size + (run_dir / "stderr.log").stat().st_size, 128)

    def test_forge_test_refuses_enabled_ffi(self) -> None:
        self.mock_tool("forge", '''
if "--version" in sys.argv:
    print("forge mock 1.0")
elif "test" in sys.argv:
    print("[PASS] unsafe test")
''', config_ffi=True)
        completed = self.run_cli("run", "forge-test")
        self.assertEqual(completed.returncode, 2)
        result, _ = self.result(completed)
        self.assertEqual(result["status"], "incomplete")
        self.assertIn("FFI", result["spawn_error"])
        self.assertIsNone(result["replay_receipt"])

    def test_second_run_reuses_exact_manifest_and_carries_both_receipts(self) -> None:
        self.mock_tool("forge", '''
if "--version" in sys.argv:
    print("forge mock 1.0")
elif "test" in sys.argv:
    print("Ran 1 test for test/Vault.t.sol:VaultTest")
    print("[PASS] testSolvency()")
''')
        selectors = ("--match-contract", "VaultTest", "--match-test", "testSolvency")
        primary = self.run_cli("run", "forge-test", *selectors)
        self.assertEqual(primary.returncode, 0, primary.stderr)
        first_result, first_dir = self.result(primary)
        second = self.run_cli(
            "run", "forge-test", *selectors,
            "--reuse-manifest", str(first_dir / "manifest.json"),
            "--independent-verifier", "reviewer-two",
        )
        self.assertEqual(second.returncode, 0, second.stderr)
        second_result, second_dir = self.result(second)
        self.assertEqual(second_result["status"], "pass")
        self.assertEqual(second_result["manifest_sha256"], first_result["manifest_sha256"])
        self.assertEqual((second_dir / "manifest.json").read_bytes(), (first_dir / "manifest.json").read_bytes())
        self.assertEqual((second_dir / "source_snapshot.tar").read_bytes(), (first_dir / "source_snapshot.tar").read_bytes())
        primary_receipt = json.loads((second_dir / "primary_replay_receipt.json").read_text())
        independent_receipt = json.loads((second_dir / "independent_replay_receipt.json").read_text())
        self.assertEqual(primary_receipt["kind"], "replay")
        self.assertEqual(independent_receipt["kind"], "independent_replay")
        self.assertEqual(independent_receipt["method"], "independent_replay")
        self.assertEqual(independent_receipt["verifier"], "reviewer-two")
        self.assertEqual(independent_receipt["log_ref"],
                         "independent_stdout.log#sha256=" + hashlib.sha256((second_dir / "independent_stdout.log").read_bytes()).hexdigest())
        self.assertIn("primary_replay_receipt.json#sha256=" + hashlib.sha256((second_dir / "primary_replay_receipt.json").read_bytes()).hexdigest(),
                      second_result["primary_artifact_refs"])
        self.assertIn("independent_replay_receipt.json#sha256=" + hashlib.sha256((second_dir / "independent_replay_receipt.json").read_bytes()).hexdigest(),
                      second_result["independent_artifact_refs"])

    def test_reuse_refuses_changed_source(self) -> None:
        self.mock_tool("forge", '''
if "--version" in sys.argv:
    print("forge mock 1.0")
elif "test" in sys.argv:
    print("[PASS] testSolvency()")
''')
        primary = self.run_cli("run", "forge-test")
        self.assertEqual(primary.returncode, 0, primary.stderr)
        _, first_dir = self.result(primary)
        (self.project / "src" / "Vault.sol").write_text("pragma solidity ^0.8.20; contract Vault { uint x; }\n")
        second = self.run_cli("run", "forge-test", "--reuse-manifest", str(first_dir / "manifest.json"))
        self.assertEqual(second.returncode, 2)
        self.assertIn("prior manifest differs", second.stderr)

    def test_output_cannot_equal_project(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(SCRIPT), "manifest", "--project", str(self.project),
             "--output-dir", str(self.project)],
            text=True, capture_output=True, env=self.env, timeout=20,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("must not equal", completed.stderr)

    def test_dependency_tree_is_hashed_and_excluded_import_fails_closed(self) -> None:
        dependency = self.project / "node_modules" / "vendor" / "Helper.sol"
        dependency.parent.mkdir(parents=True)
        dependency.write_text("pragma solidity ^0.8.20; contract Helper {}\n")
        first = self.run_cli("manifest")
        self.assertEqual(first.returncode, 0, first.stderr)
        first_hash = json.loads((self.output / "manifest.json").read_text())["source_tree_sha256"]
        dependency.write_text("pragma solidity ^0.8.20; contract Helper { uint x; }\n")
        second = self.run_cli("manifest")
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertNotEqual(json.loads((self.output / "manifest.json").read_text())["source_tree_sha256"], first_hash)
        generated = self.project / "out" / "Generated.sol"
        generated.parent.mkdir()
        generated.write_text("pragma solidity ^0.8.20; contract Generated {}\n")
        (self.project / "src" / "Vault.sol").write_text('pragma solidity ^0.8.20; import "../out/Generated.sol"; contract Vault {}\n')
        self.mock_tool("forge", 'print("forge mock 1.0")\n')
        refused = self.run_cli("run", "forge-build")
        self.assertEqual(refused.returncode, 2)
        self.assertIn("imports an excluded generated directory", refused.stderr)

    def test_sensitive_input_requires_sanitized_checkout_but_templates_are_hashed(self) -> None:
        template = self.project / ".env.deploy.example"
        template.write_text("RPC_URL=${RPC_URL}\n")
        self.assertEqual(self.run_cli("manifest").returncode, 0)
        secret = self.project / ".env.local"
        secret.write_text("RPC_URL=https://private.example/key\n")
        refused = self.run_cli("manifest")
        self.assertEqual(refused.returncode, 2)
        self.assertIn("sanitized checkout", refused.stderr)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO requires POSIX")
    def test_non_regular_source_is_rejected_before_snapshot(self) -> None:
        os.mkfifo(self.project / "src" / "blocked.pipe")
        refused = self.run_cli("manifest")
        self.assertEqual(refused.returncode, 2)
        self.assertIn("non-regular file", refused.stderr)

    def test_source_mutation_during_forge_test_blocks_receipt(self) -> None:
        self.mock_tool("forge", '''
if "--version" in sys.argv:
    print("forge mock 1.0")
elif "test" in sys.argv:
    with open("src/Vault.sol", "a") as stream:
        stream.write("// mutated during analysis\\n")
    print("[PASS] testSolvency()")
    print("Suite result: ok. 1 passed; 0 failed")
''')
        completed = self.run_cli("run", "forge-test")
        self.assertEqual(completed.returncode, 2)
        result, _ = self.result(completed)
        self.assertTrue(result["source_drift"])
        self.assertEqual(result["status"], "incomplete")
        self.assertIsNone(result["replay_receipt"])

    def test_effective_compiler_comes_from_foundry_build_info(self) -> None:
        info = self.project / "out" / "build-info" / "one.json"
        info.parent.mkdir(parents=True)
        info.write_text(json.dumps({"solcLongVersion": "0.8.24", "output": {}}))
        self.mock_tool("forge", '''
if "--version" in sys.argv:
    print("forge mock 1.0")
elif "test" in sys.argv:
    print("[PASS] testSolvency()")
    print("Suite result: ok. 1 passed; 0 failed")
''')
        self.mock_tool("solc", 'print("solc, the solidity compiler commandline interface\\nVersion: 0.8.35")\n')
        completed = self.run_cli("run", "forge-test")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        result, run_dir = self.result(completed)
        manifest = json.loads((run_dir / "manifest.json").read_text())
        self.assertEqual(manifest["environment"]["compiler"], "Solc 0.8.24")
        self.assertEqual(result["effective_compiler_versions"], ["0.8.24"])
        self.assertIn("0.8.35", manifest["environment"]["tool_versions"]["solc"])

    def test_halmos_counterexample_run_is_findings_with_hashed_artifact(self) -> None:
        self.mock_tool("halmos", '''
if "--version" in sys.argv:
    print("halmos mock 0.3.3")
    sys.exit(0)
out = sys.argv[sys.argv.index("--json-output") + 1]
open(out, "w").write(json.dumps({"exitcode": 1, "test_results": {"test/V.t.sol:VC": [
    {"name": "check_bug(uint256)", "exitcode": 1, "num_models": 1, "models": [{"x": "1"}]}]}}))
print("[FAIL] check_bug")
sys.exit(1)
''')
        completed = self.run_cli("run", "halmos", "--match-test", "check_bug", "--match-contract", "VC")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        result, run_dir = self.result(completed)
        self.assertEqual(result["status"], "findings")
        self.assertEqual(result["candidate_count"], 1)
        self.assertEqual(result["tool_version"], "halmos mock 0.3.3")
        self.assertIn(["--match-test", r"^check_bug\("],
                      [result["argv"][i:i + 2] for i in range(len(result["argv"]) - 1)])
        self.assertTrue((run_dir / "halmos.json").is_file())
        self.assertTrue(any(ref.startswith("halmos.json#sha256=") for ref in result["evidence_artifact_refs"]))

    def test_halmos_nonzero_process_exit_cannot_be_a_pass(self) -> None:
        self.mock_tool("halmos", '''
if "--version" in sys.argv:
    print("halmos mock 0.3.3")
    sys.exit(0)
out = sys.argv[sys.argv.index("--json-output") + 1]
open(out, "w").write(json.dumps({"exitcode": 0, "test_results": {"test/V.t.sol:VC": [
    {"name": "check_ok(uint256)", "exitcode": 0, "num_models": 0, "models": []}]}}))
sys.exit(2)
''')
        completed = self.run_cli("run", "halmos", "--match-test", "check_ok")
        self.assertEqual(completed.returncode, 2, completed.stderr)
        result, _ = self.result(completed)
        self.assertEqual(result["status"], "incomplete")
        self.assertIn("nonzero", result["status_reason"])


class HalmosClassifyTests(unittest.TestCase):
    """classify_halmos: counterexample vs bounded proof vs undecided/parse errors."""

    def setUp(self) -> None:
        sys.path.insert(0, str(SCRIPT.parent))
        import importlib
        self.ra = importlib.import_module("run_analysis")
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.dir = Path(self.temp.name)

    def _write(self, data: dict) -> Path:
        path = self.dir / "halmos.json"
        path.write_text(json.dumps(data))
        return path

    def test_counterexample_with_model_is_findings(self) -> None:
        path = self._write({"exitcode": 1, "test_results": {"T:C": [
            {"name": "check_bug(uint256)", "exitcode": 1, "num_models": 1, "models": [{"x": "1"}]},
            {"name": "check_ok(uint256)", "exitcode": 0, "num_models": 0, "models": []}]}})
        status, _, candidates = self.ra.classify_halmos(path)
        self.assertEqual((status, candidates), ("findings", 1))

    def test_all_pass_is_bounded_pass(self) -> None:
        path = self._write({"exitcode": 0, "test_results": {"T:C": [
            {"name": "check_ok(uint256)", "exitcode": 0, "num_models": 0, "models": []}]}})
        status, _, candidates = self.ra.classify_halmos(path)
        self.assertEqual((status, candidates), ("pass", 0))

    def test_nonzero_overall_exit_is_incomplete_even_if_tests_pass(self) -> None:
        path = self._write({"exitcode": 2, "test_results": {"T:C": [
            {"name": "check_ok(uint256)", "exitcode": 0, "num_models": 0, "models": []}]}})
        self.assertEqual(self.ra.classify_halmos(path)[0], "incomplete")

    def test_wrong_property_result_is_incomplete(self) -> None:
        path = self._write({"exitcode": 0, "test_results": {"T:C": [
            {"name": "check_bug2(uint256)", "exitcode": 0, "num_models": 0, "models": []}]}})
        self.assertEqual(self.ra.classify_halmos(path, "check_bug", "C")[0], "incomplete")

    def test_nonzero_without_model_is_incomplete(self) -> None:
        path = self._write({"exitcode": 1, "test_results": {"T:C": [
            {"name": "check_hard(uint256)", "exitcode": 5, "num_models": 0, "models": []}]}})
        status, _, candidates = self.ra.classify_halmos(path)
        self.assertEqual((status, candidates), ("incomplete", None))

    def test_no_tests_is_incomplete(self) -> None:
        self.assertEqual(self.ra.classify_halmos(self._write({"exitcode": 0, "test_results": {}}))[0], "incomplete")

    def test_missing_or_unparseable_is_incomplete(self) -> None:
        self.assertEqual(self.ra.classify_halmos(self.dir / "absent.json")[0], "incomplete")
        bad = self.dir / "bad.json"
        bad.write_text("{not json")
        self.assertEqual(self.ra.classify_halmos(bad)[0], "incomplete")


if __name__ == "__main__":
    unittest.main()
