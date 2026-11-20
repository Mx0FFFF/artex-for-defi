"""Sourcify response bytes and source paths are bounded before reuse."""

import hashlib
import tempfile
import unittest
from pathlib import Path

import fetch_verified_source as source


class VerifiedSourceTests(unittest.TestCase):
    def test_runtime_code_hash_and_source_path_validation(self):
        blob = bytes.fromhex("6001600055")
        self.assertEqual(source.runtime_code_hash({
            "runtimeBytecode": {"onchainBytecode": "0x" + blob.hex()},
        }), hashlib.sha256(blob).hexdigest())
        for raw in ("0x123", "0xzz", "0x" + "11" * (source.MAX_CODE + 1)):
            with self.assertRaises(ValueError):
                source.runtime_code_hash({"runtimeBytecode": {"onchainBytecode": raw}})
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("../Vault.sol", "src//Vault.sol", "src/./Vault.sol", "/Vault.sol", "src\\Vault.sol"):
                with self.assertRaises(ValueError):
                    source.safe_source_path(root, name)


if __name__ == "__main__":
    unittest.main()
