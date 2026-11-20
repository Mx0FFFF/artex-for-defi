#!/usr/bin/env python3
"""Select research cards for a DeFi review and account for all 43 cards.

Cards are hypothesis guidance, not executable detectors or findings. The complete
selection ledger is emitted even when only a small set of cards is retrieved.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any


DATA_DIR = Path(__file__).resolve().parents[1] / "data"
TRACKS = ("evm", "cross_chain", "solana", "move")
PROTOCOLS = ("generic", "vault", "lending", "amm", "staking", "governance", "bridge", "perps", "router")
DEFAULT_MAX_CARDS = 15

# These cards need an observed feature before a protocol label alone can select
# them. In particular, an ordinary AMM is not necessarily a stable or tick AMM.
REQUIRED_ANY_FEATURE = {
    "EVM-07": {"multicall"},
    "EVM-14": {"transient", "eip7702", "compiler"},
    "ECO-09": {"l2"},
    "ECO-10": {"stable_amm"},
    "ECO-11": {"concentrated_liquidity"},
    "ECO-13": {"queues", "async"},
    "X12": {"token2022"},
    "X14": {"hot_potato", "flash_liquidity"},
}


class CatalogError(ValueError):
    """Invalid catalog data or selection request."""


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CatalogError(f"cannot read {path}: {exc}") from exc


def load_data(data_dir: Path = DATA_DIR) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    """Load the copied pack and reject changes not reflected in its version file."""
    version = _read_json(data_dir / "catalog_version.json")
    if not isinstance(version, dict) or version.get("catalog_schema_version") != "1.0":
        raise CatalogError("unsupported catalog version")
    for name in ("detector_catalog.json", "sources.json", "selection_rules.json"):
        expected = version.get("files", {}).get(name)
        if not isinstance(expected, str):
            raise CatalogError(f"missing SHA-256 for {name}")
        try:
            actual = hashlib.sha256((data_dir / name).read_bytes()).hexdigest()
        except OSError as exc:
            raise CatalogError(f"cannot read {name}: {exc}") from exc
        if actual != expected:
            raise CatalogError(f"SHA-256 mismatch for {name}; review and version this change")
    catalog = _read_json(data_dir / "detector_catalog.json")
    sources = _read_json(data_dir / "sources.json")
    rules = _read_json(data_dir / "selection_rules.json")
    validate_data(catalog, sources, rules, version)
    return catalog, sources, rules, version


def validate_data(
    catalog: dict[str, Any],
    sources: list[dict[str, Any]],
    rules: dict[str, Any],
    version: dict[str, Any],
) -> None:
    if not isinstance(catalog, dict) or catalog.get("schema_version") != version.get("catalog_schema_version"):
        raise CatalogError("catalog schema version does not match version record")
    cards = catalog.get("cards")
    if not isinstance(cards, list) or len(cards) != version.get("expected_cards"):
        raise CatalogError("catalog card count does not match version record")
    if not isinstance(sources, list) or len(sources) != version.get("expected_sources"):
        raise CatalogError("source count does not match version record")
    if not isinstance(rules, dict) or rules.get("schema_version") != "1.0" or not isinstance(rules.get("rules"), dict):
        raise CatalogError("unsupported selection rules")

    source_ids: set[str] = set()
    for source in sources:
        if not isinstance(source, dict) or not isinstance(source.get("id"), str):
            raise CatalogError("source has no ID")
        sid = source["id"]
        if sid in source_ids:
            raise CatalogError(f"duplicate source ID: {sid}")
        source_ids.add(sid)
        urls = source.get("urls")
        if not isinstance(urls, list) or not urls or any(not isinstance(u, str) or not u.startswith("https://") for u in urls):
            raise CatalogError(f"source {sid} has no HTTPS URL")

    card_ids: set[str] = set()
    for card in cards:
        if not isinstance(card, dict) or not isinstance(card.get("id"), str):
            raise CatalogError("card has no ID")
        cid = card["id"]
        if cid in card_ids:
            raise CatalogError(f"duplicate card ID: {cid}")
        card_ids.add(cid)
        if card.get("track") not in ("evm", "evm_economics", "cross_chain", "solana", "move"):
            raise CatalogError(f"card {cid} has unknown track")
        if not isinstance(card.get("title"), str) or not card["title"].strip():
            raise CatalogError(f"card {cid} has no title")
        if not isinstance(card.get("sections"), dict) or not card["sections"]:
            raise CatalogError(f"card {cid} has no test guidance")
        if not isinstance(card.get("source_ids"), list) or not card["source_ids"]:
            raise CatalogError(f"card {cid} has no primary sources")
        for sid in card["source_ids"]:
            if sid not in source_ids:
                raise CatalogError(f"card {cid} refers to unknown source {sid}")
    for card in cards:
        for related in card.get("related_ids", []):
            if related not in card_ids:
                raise CatalogError(f"card {card['id']} refers to unknown related card {related}")
    if set(rules["rules"]) != card_ids:
        raise CatalogError("selection rules must cover every card exactly once")
    known_features = set()
    for cid, rule in rules["rules"].items():
        if not isinstance(rule, dict) or not isinstance(rule.get("baseline"), bool):
            raise CatalogError(f"invalid selection rule for {cid}")
        if not isinstance(rule.get("protocols"), list) or not isinstance(rule.get("features"), list):
            raise CatalogError(f"invalid protocol/feature tags for {cid}")
        if any(p not in PROTOCOLS for p in rule["protocols"]):
            raise CatalogError(f"unknown protocol tag for {cid}")
        if any(not isinstance(f, str) or not f for f in rule["features"]):
            raise CatalogError(f"invalid feature tag for {cid}")
        known_features.update(rule["features"])
    if any(cid not in card_ids or not required <= known_features for cid, required in REQUIRED_ANY_FEATURE.items()):
        raise CatalogError("required-feature rules are inconsistent with catalog tags")


def _track_matches(card_track: str, requested: str, protocol: str, features: set[str]) -> bool:
    if requested == "evm":
        return card_track in ("evm", "evm_economics") or (
            card_track == "cross_chain" and (protocol == "bridge" or "bridge" in features)
        )
    return card_track == requested


def parse_blocks(raw_blocks: list[str]) -> dict[str, str]:
    blocks: dict[str, str] = {}
    for raw in raw_blocks:
        cid, sep, reason = raw.partition("=")
        if not sep or not cid.strip() or not reason.strip():
            raise CatalogError("--block must be ID=reason")
        cid, reason = cid.strip(), reason.strip()
        if cid in blocks:
            raise CatalogError(f"duplicate block for {cid}")
        blocks[cid] = reason
    return blocks


def select_cards(
    catalog: dict[str, Any],
    sources: list[dict[str, Any]],
    rules: dict[str, Any],
    *,
    track: str,
    protocol: str,
    features: set[str] | None = None,
    max_cards: int = DEFAULT_MAX_CARDS,
    blocks: dict[str, str] | None = None,
) -> dict[str, Any]:
    if track not in TRACKS or protocol not in PROTOCOLS:
        raise CatalogError("unsupported track or protocol")
    if not 1 <= max_cards <= len(catalog["cards"]):
        raise CatalogError("max_cards must be within the catalog size")
    features, blocks = set(features or set()), dict(blocks or {})
    known_features = {f for rule in rules["rules"].values() for f in rule["features"]}
    unknown_features = features - known_features
    if unknown_features:
        raise CatalogError(f"unknown feature(s): {', '.join(sorted(unknown_features))}")
    card_by_id = {card["id"]: card for card in catalog["cards"]}
    unknown_blocks = set(blocks) - set(card_by_id)
    if unknown_blocks:
        raise CatalogError(f"unknown blocked card(s): {', '.join(sorted(unknown_blocks))}")
    source_by_id = {source["id"]: source for source in sources}

    ledger: dict[str, dict[str, str]] = {}
    candidates: list[tuple[int, int, str, list[str]]] = []
    for index, card in enumerate(catalog["cards"]):
        cid = card["id"]
        rule = rules["rules"][cid]
        if not _track_matches(card["track"], track, protocol, features):
            ledger[cid] = {"id": cid, "track": card["track"], "status": "deselected", "reason": "track_not_selected"}
            continue
        required = REQUIRED_ANY_FEATURE.get(cid, set())
        if required and not required & features:
            ledger[cid] = {
                "id": cid, "track": card["track"], "status": "deselected",
                "reason": "missing_required_feature:" + "|".join(sorted(required)),
            }
            continue
        matching_features = sorted(features.intersection(rule["features"]))
        matching_protocol = protocol in rule["protocols"]
        reasons = ([] if not rule["baseline"] else ["baseline"])
        if matching_protocol:
            reasons.append("protocol:" + protocol)
        reasons.extend("feature:" + feature for feature in matching_features)
        if not reasons:
            ledger[cid] = {"id": cid, "track": card["track"], "status": "deselected", "reason": "no_matching_protocol_or_feature"}
            continue
        score = int(rule["baseline"]) + 2 * int(matching_protocol) + 3 * len(matching_features)
        candidates.append((-score, index, cid, reasons))

    chosen = 0
    for _, _, cid, reasons in sorted(candidates):
        card = card_by_id[cid]
        if cid in blocks:
            ledger[cid] = {"id": cid, "track": card["track"], "status": "blocked", "reason": blocks[cid]}
        elif chosen < max_cards:
            ledger[cid] = {"id": cid, "track": card["track"], "status": "selected", "reason": ",".join(reasons)}
            chosen += 1
        else:
            ledger[cid] = {"id": cid, "track": card["track"], "status": "deselected", "reason": "deferred_by_max_cards"}
    unused_blocks = set(blocks) - {cid for cid, row in ledger.items() if row["status"] == "blocked"}
    if unused_blocks:
        raise CatalogError(f"blocked card(s) are outside selected scope: {', '.join(sorted(unused_blocks))}")

    ordered_ledger = [ledger[card["id"]] for card in catalog["cards"]]
    selected_cards = []
    for card in catalog["cards"]:
        if ledger[card["id"]]["status"] != "selected":
            continue
        selected_cards.append({
            "id": card["id"], "title": card["title"], "track": card["track"],
            "selection_reason": ledger[card["id"]]["reason"],
            "guidance_markdown": card["guidance_markdown"], "sections": card["sections"],
            "source_ids": card["source_ids"],
            "sources": [{"id": sid, "urls": source_by_id[sid]["urls"], "accessed": source_by_id[sid].get("accessed")} for sid in card["source_ids"]],
            "related_ids": card.get("related_ids", []),
        })
    counts = {status: sum(row["status"] == status for row in ordered_ledger) for status in ("selected", "deselected", "blocked")}
    return {
        "catalog_schema_version": catalog["schema_version"],
        "research_date": catalog.get("research_date"),
        "selection": {"track": track, "protocol": protocol, "features": sorted(features), "max_cards": max_cards},
        "notice": "Research hypotheses only; selection is not a vulnerability finding or test result.",
        "counts": counts,
        "selected_cards": selected_cards,
        "ledger": ordered_ledger,
    }


def _short(value: str, limit: int = 220) -> str:
    value = " ".join(value.split())
    return value if len(value) <= limit else value[: limit - 1].rstrip() + "…"


def render_text(result: dict[str, Any]) -> str:
    sel, counts = result["selection"], result["counts"]
    out = [
        f"Research catalog {result['catalog_schema_version']} | {sel['track']} / {sel['protocol']} | features: {', '.join(sel['features']) or 'none'}",
        f"Selected {counts['selected']}; blocked {counts['blocked']}; deselected {counts['deselected']} (43-card ledger below).",
        result["notice"],
    ]
    for card in result["selected_cards"]:
        sections = card["sections"]
        mechanism = next((value for key, value in sections.items() if key.startswith("Mechanism")), "")
        test = next((value for key, value in sections.items() if key.startswith("Test")), "")
        out.extend((f"\n{card['id']} {card['title']} [{card['selection_reason']}]", f"  Mechanism: {_short(mechanism)}", f"  Test: {_short(test)}"))
        for source in card["sources"]:
            for url in source["urls"]:
                out.append(f"  Source {source['id']}: {url}")
    grouped: dict[tuple[str, str], list[str]] = defaultdict(list)
    for row in result["ledger"]:
        grouped[(row["status"], row["reason"])].append(row["id"])
    out.append("\nComplete ledger (status / reason: IDs):")
    for (status, reason), ids in sorted(grouped.items()):
        out.append(f"  {status} / {reason}: {', '.join(ids)}")
    return "\n".join(out) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("validate", help="check copied catalog hashes, unique IDs, source resolution and rules")
    sub.add_parser("tags", help="list supported tracks, protocols and observed feature tags")
    select = sub.add_parser("select", help="retrieve a bounded set of relevant hypothesis cards")
    select.add_argument("--track", required=True, choices=TRACKS)
    select.add_argument("--protocol", required=True, choices=PROTOCOLS)
    select.add_argument("--feature", action="append", default=[], help="observed feature tag; repeatable")
    select.add_argument("--max-cards", type=int, default=DEFAULT_MAX_CARDS)
    select.add_argument("--block", action="append", default=[], metavar="ID=REASON", help="record an applicable card blocked by missing evidence/tooling")
    select.add_argument("--format", choices=("text", "json"), default="text")
    select.add_argument("--output", type=Path, help="write result to an artifact file instead of stdout")
    args = parser.parse_args(argv)
    try:
        catalog, sources, rules, version = load_data()
        if args.command == "validate":
            print(f"OK: {len(catalog['cards'])} cards, {len(sources)} sources, {len(rules['rules'])} rules; hashes and references verified")
            return 0
        if args.command == "tags":
            features = sorted({f for rule in rules["rules"].values() for f in rule["features"]})
            print("tracks: " + ", ".join(TRACKS))
            print("protocols: " + ", ".join(PROTOCOLS))
            print("features: " + ", ".join(features))
            return 0
        result = select_cards(catalog, sources, rules, track=args.track, protocol=args.protocol,
                              features=set(args.feature), max_cards=args.max_cards, blocks=parse_blocks(args.block))
        output = json.dumps(result, indent=2, ensure_ascii=False) + "\n" if args.format == "json" else render_text(result)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
        else:
            sys.stdout.write(output)
        return 0
    except CatalogError as exc:
        print(f"catalog error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
