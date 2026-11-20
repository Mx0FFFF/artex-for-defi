import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from inventory import inventory  # noqa: E402


@unittest.skipUnless(importlib.util.find_spec("slither") is not None, "Slither unavailable")
class InventoryTests(unittest.TestCase):
    def test_entrypoint_state_and_external_call_graph(self):
        source = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
interface Token { function transfer(address,uint256) external returns (bool); }
contract Vault {
    uint256 public balance;
    Token public token;
    constructor(Token t) { token = t; }
    function deposit(uint256 amount) external { balance += amount; }
    function withdraw(uint256 amount) external { balance -= amount; token.transfer(msg.sender, amount); }
}
"""
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "Vault.sol"
            path.write_text(source, encoding="utf-8")
            try:
                result = inventory(path)
            except Exception as exc:
                if "solc" in str(exc).lower():
                    self.skipTest(f"compiler unavailable: {exc}")
                raise
            self.assertEqual(result["summary"]["contracts"], 1)
            self.assertEqual(result["summary"]["entry_points"], 2)
            self.assertEqual(result["summary"]["external_call_entry_points"], 1)
            withdraw = next(f for f in result["contracts"][0]["entry_points"] if f["name"] == "withdraw")
            self.assertTrue(any("balance" in name for name in withdraw["state_writes"]))
            self.assertTrue(any("transfer" in call for call in withdraw["external_calls"]))


if __name__ == "__main__":
    unittest.main()
