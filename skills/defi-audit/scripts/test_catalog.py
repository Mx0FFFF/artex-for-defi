"""Focused checks for catalog integrity, bounded selection and coverage ledger."""

from __future__ import annotations

import copy
import json
import shutil
import tempfile
import unittest
from pathlib import Path

import catalog


class CatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.data = catalog.load_data()

    def select(self, **kwargs):
        cards, sources, rules, _ = self.data
        return catalog.select_cards(cards, sources, rules, **kwargs)

    def test_copied_pack_is_complete_and_resolved(self) -> None:
        cards, sources, rules, version = self.data
        self.assertEqual(len(cards["cards"]), 43)
        self.assertEqual(len(sources), 71)
        self.assertEqual(len(rules["rules"]), 43)
        self.assertEqual(version["expected_cards"], 43)

    def test_lending_oracle_selection_is_bounded_and_every_card_is_accounted_for(self) -> None:
        result = self.select(track="evm", protocol="lending", features={"oracle"}, max_cards=15)
        selected = {card["id"] for card in result["selected_cards"]}
        self.assertTrue({"EVM-01", "ECO-04", "ECO-05", "ECO-07", "ECO-08"} <= selected)
        self.assertLess(len(selected), 43)
        self.assertEqual(len(result["ledger"]), 43)
        self.assertEqual(set(result["counts"]), {"selected", "deselected", "blocked"})
        self.assertEqual(sum(result["counts"].values()), 43)
        self.assertTrue(all(card["sources"] and card["sources"][0]["urls"][0].startswith("https://") for card in result["selected_cards"]))

    def test_feature_gate_prevents_unrelated_l2_and_tick_cards(self) -> None:
        result = self.select(track="evm", protocol="amm", features={"oracle"}, max_cards=15)
        rows = {row["id"]: row for row in result["ledger"]}
        for cid in ("ECO-09", "ECO-10", "ECO-11"):
            self.assertEqual(rows[cid]["status"], "deselected")
            self.assertTrue(rows[cid]["reason"].startswith("missing_required_feature:"))
        self.assertEqual(rows["X06"]["reason"], "track_not_selected")

    def test_solana_retrieval_stays_in_solana_track(self) -> None:
        result = self.select(track="solana", protocol="vault", features={"token2022"}, max_cards=15)
        selected = {card["id"] for card in result["selected_cards"]}
        self.assertTrue({"X06", "X07", "X12"} <= selected)
        self.assertTrue(all(card["track"] == "solana" for card in result["selected_cards"]))

    def test_blocked_analysis_is_recorded_not_passed(self) -> None:
        result = self.select(track="evm", protocol="vault", features=set(), max_cards=2,
                             blocks={"EVM-01": "source build unavailable"})
        rows = {row["id"]: row for row in result["ledger"]}
        self.assertEqual(rows["EVM-01"], {"id": "EVM-01", "track": "evm", "status": "blocked", "reason": "source build unavailable"})
        self.assertEqual(result["counts"]["blocked"], 1)
        self.assertEqual(result["counts"]["selected"], 2)
        self.assertIn("EVM-01", catalog.render_text(result))

    def test_duplicate_id_and_unresolved_source_fail_closed(self) -> None:
        cards, sources, rules, version = self.data
        duplicated = copy.deepcopy(cards)
        duplicated["cards"][1]["id"] = duplicated["cards"][0]["id"]
        with self.assertRaisesRegex(catalog.CatalogError, "duplicate card ID"):
            catalog.validate_data(duplicated, sources, rules, version)
        bad_source = copy.deepcopy(cards)
        bad_source["cards"][0]["source_ids"] = ["MISSING"]
        with self.assertRaisesRegex(catalog.CatalogError, "unknown source"):
            catalog.validate_data(bad_source, sources, rules, version)

    def test_hash_mismatch_requires_version_update(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            for name in ("detector_catalog.json", "sources.json", "selection_rules.json", "catalog_version.json"):
                shutil.copyfile(catalog.DATA_DIR / name, directory / name)
            data = json.loads((directory / "detector_catalog.json").read_text())
            data["cards"][0]["title"] = "Changed without versioning"
            (directory / "detector_catalog.json").write_text(json.dumps(data))
            with self.assertRaisesRegex(catalog.CatalogError, "SHA-256 mismatch"):
                catalog.load_data(directory)

    def test_invalid_request_is_not_silently_broadened(self) -> None:
        with self.assertRaisesRegex(catalog.CatalogError, "unknown feature"):
            self.select(track="evm", protocol="vault", features={"orcale"})
        with self.assertRaisesRegex(catalog.CatalogError, "outside selected scope"):
            self.select(track="evm", protocol="vault", features=set(), blocks={"X14": "no runtime"})


if __name__ == "__main__":
    unittest.main()
