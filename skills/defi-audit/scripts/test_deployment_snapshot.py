"""Offline JSON-RPC tests; no live chain or credential is used."""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import URLError

import deployment_snapshot as snap


ADDRESS = "0x" + "a1" * 20
IMPLEMENTATION = "0x" + "b2" * 20
ADMIN = "0x" + "c3" * 20
BEACON = "0x" + "d4" * 20
BLOCK_HASH = "0x" + "ef" * 32


class Response:
    def __init__(self, body: bytes):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self, limit: int):
        return self.body[:limit]


def slot_address(address: str) -> str:
    return "0x" + "00" * 12 + address[2:]


class MockRPC:
    def __init__(self, chain_id: int = 1, error_method: str | None = None, reorg_after: bool = False):
        self.chain_id = chain_id
        self.error_method = error_method
        self.reorg_after = reorg_after
        self.calls = []

    def __call__(self, request, timeout):
        payload = json.loads(request.data)
        method, params = payload["method"], payload["params"]
        self.calls.append((method, params))
        if method == self.error_method:
            result = {"jsonrpc": "2.0", "id": payload["id"], "error": {"message": "secret https://rpc.example/APIKEY"}}
        else:
            if method == "eth_chainId":
                value = hex(self.chain_id)
            elif method == "eth_getBlockByNumber":
                block_reads = sum(name == "eth_getBlockByNumber" for name, _ in self.calls)
                value = {"number": params[0], "hash": "0x" + "12" * 32 if self.reorg_after and block_reads > 1 else BLOCK_HASH}
            elif method == "eth_getCode":
                value = "0x6001600055"
            elif method == "eth_getStorageAt":
                values = {
                    snap.SLOTS["implementation"]: slot_address(IMPLEMENTATION),
                    snap.SLOTS["admin"]: slot_address(ADMIN),
                    snap.SLOTS["beacon"]: slot_address(BEACON),
                }
                value = values[params[1]]
            else:
                raise AssertionError(f"unexpected RPC method: {method}")
            result = {"jsonrpc": "2.0", "id": payload["id"], "result": value}
        return Response(json.dumps(result).encode())


class DeploymentSnapshotTests(unittest.TestCase):
    def test_pinned_snapshot_decodes_slots_without_following_them(self):
        mock = MockRPC()
        with patch.object(snap, "_open_https", mock):
            rpc = snap.ReadOnlyRPC("https://rpc.example/secret?key=HIDDEN")
            result = snap.snapshot(rpc, chain_id=1, block_number=100, addresses=[ADDRESS.upper().replace("0X", "0x")])
        self.assertEqual(result["chain_id"], 1)
        self.assertEqual(result["block_number"], 100)
        self.assertEqual(result["block_hash"], BLOCK_HASH)
        entry = result["addresses"][0]
        self.assertEqual(entry["address"], ADDRESS)
        self.assertEqual(entry["code_bytes"], 5)
        self.assertEqual(entry["code_sha256"], hashlib.sha256(bytes.fromhex("6001600055")).hexdigest())
        self.assertEqual(entry["erc1967_slots"]["implementation"]["address"], IMPLEMENTATION)
        self.assertEqual(entry["erc1967_slots"]["admin"]["address"], ADMIN)
        self.assertEqual(entry["erc1967_slots"]["beacon"]["address"], BEACON)
        self.assertEqual([method for method, _ in mock.calls], [
            "eth_chainId", "eth_getBlockByNumber", "eth_getCode",
            "eth_getStorageAt", "eth_getStorageAt", "eth_getStorageAt",
            "eth_getBlockByNumber",
        ])
        self.assertFalse(any(IMPLEMENTATION in str(params) for _, params in mock.calls))
        self.assertNotIn("HIDDEN", json.dumps(result))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "deployment.json"
            digest = snap.write_snapshot(path, result)
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)
            self.assertIn(digest, path.with_name("deployment.json.sha256").read_text())
            with self.assertRaisesRegex(snap.SnapshotError, "already exists"):
                snap.write_snapshot(path, result)

    def test_chain_mismatch_stops_before_code_queries(self):
        mock = MockRPC(chain_id=10)
        with patch.object(snap, "_open_https", mock):
            with self.assertRaisesRegex(snap.SnapshotError, "chain ID mismatch"):
                snap.snapshot(snap.ReadOnlyRPC("https://rpc.example/secret"), chain_id=1,
                              block_number=100, addresses=[ADDRESS])
        self.assertEqual([method for method, _ in mock.calls], ["eth_chainId"])

    def test_reorg_during_number_pinned_reads_is_rejected(self):
        mock = MockRPC(reorg_after=True)
        with patch.object(snap, "_open_https", mock):
            with self.assertRaisesRegex(snap.SnapshotError, "pinned block changed"):
                snap.snapshot(snap.ReadOnlyRPC("https://rpc.example/"), chain_id=1,
                              block_number=100, addresses=[ADDRESS])

    def test_address_validation_stops_before_network_and_duplicate(self):
        mock = MockRPC()
        with patch.object(snap, "_open_https", mock):
            rpc = snap.ReadOnlyRPC("https://rpc.example/")
            for invalid in ("0x1234", "0x" + "zz" * 20):
                with self.assertRaisesRegex(snap.SnapshotError, "address"):
                    snap.snapshot(rpc, chain_id=1, block_number=100, addresses=[invalid])
            with self.assertRaisesRegex(snap.SnapshotError, "duplicate"):
                snap.snapshot(rpc, chain_id=1, block_number=100, addresses=[ADDRESS, ADDRESS.upper().replace("0X", "0x")])
        self.assertEqual(mock.calls, [])

    def test_secret_redaction_on_transport_and_json_rpc_errors(self):
        secret_url = "https://rpc.example/TOPSECRET?key=TOPSECRET"
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "deployment.json"
            stderr = io.StringIO()
            with patch.dict(os.environ, {"TEST_RPC_SECRET": secret_url}), patch.object(snap, "_open_https", side_effect=URLError(secret_url)):
                with contextlib.redirect_stderr(stderr):
                    code = snap.main(["--rpc-env", "TEST_RPC_SECRET", "--expected-chain-id", "1", "--block", "100",
                                      "--address", ADDRESS, "--output", str(output)])
            self.assertEqual(code, 2)
            self.assertNotIn("TOPSECRET", stderr.getvalue())
            self.assertFalse(output.exists())
            mock = MockRPC(error_method="eth_getCode")
            with patch.object(snap, "_open_https", mock):
                with self.assertRaisesRegex(snap.SnapshotError, "returned an error") as caught:
                    snap.snapshot(snap.ReadOnlyRPC(secret_url), chain_id=1, block_number=100, addresses=[ADDRESS])
            self.assertNotIn("APIKEY", str(caught.exception))

    def test_cli_success_writes_hash_without_rpc_secret(self):
        secret_url = "https://rpc.example/TOPSECRET?key=TOPSECRET"
        mock = MockRPC()
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "deployment.json"
            stdout = io.StringIO()
            with patch.dict(os.environ, {"TEST_RPC_SECRET": secret_url}), patch.object(snap, "_open_https", mock):
                with contextlib.redirect_stdout(stdout):
                    code = snap.main(["--rpc-env", "TEST_RPC_SECRET", "--expected-chain-id", "1", "--block", "100",
                                      "--address", ADDRESS, "--output", str(output)])
            self.assertEqual(code, 0)
            self.assertTrue(output.is_file())
            self.assertTrue(output.with_name("deployment.json.sha256").is_file())
            self.assertNotIn("TOPSECRET", stdout.getvalue() + output.read_text())

    def test_malformed_or_oversized_rpc_data_is_rejected(self):
        with patch.object(snap, "_open_https", return_value=Response(b"x" * (snap.MAX_RESPONSE_BYTES + 1))):
            with self.assertRaisesRegex(snap.SnapshotError, "byte limit"):
                snap.ReadOnlyRPC("https://rpc.example/").call("eth_chainId", [])
        with self.assertRaisesRegex(snap.SnapshotError, "malformed"):
            snap._storage_address("0x1234")
        raw, address = snap._storage_address("0x" + "01" * 32)
        self.assertEqual(raw, "0x" + "01" * 32)
        self.assertIsNone(address)
        with self.assertRaisesRegex(snap.SnapshotError, "allowlist"):
            snap.ReadOnlyRPC("https://rpc.example/").call("eth_sendRawTransaction", [])


if __name__ == "__main__":
    unittest.main()
