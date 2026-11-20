#!/usr/bin/env python3
"""Extract an EVM contract's entry points and state/call edges with Slither.

This is structural evidence for hypothesis selection, never a vulnerability
finding. Run only on a repository already placed in an isolated review workspace:
compilation may execute project build hooks.
"""

import argparse
import json
import sys
from pathlib import Path


def location(mapping, project):
    if mapping is None:
        return None
    filename = Path(mapping.filename.absolute)
    try:
        label = str(filename.relative_to(project))
    except ValueError:
        label = str(filename)
    return {"file": label, "lines": list(mapping.lines)}


def inventory(project):
    try:
        from slither.slither import Slither
    except ImportError as exc:
        raise RuntimeError("Slither is not installed") from exc
    project = Path(project).resolve()
    if not project.exists():
        raise ValueError(f"project does not exist: {project}")
    slither = Slither(str(project))
    contracts = []
    for contract in slither.contracts:
        if contract.is_interface:
            continue
        functions = []
        for function in contract.functions_entry_points:
            if function.is_constructor:
                continue
            calls = sorted({str(expr) for expr in function.external_calls_as_expressions})
            functions.append({
                "name": function.name,
                "signature": function.full_name,
                "visibility": function.visibility,
                "payable": bool(function.payable),
                "modifiers": sorted({m.name for m in function.modifiers}),
                "state_reads": sorted({v.canonical_name for v in function.state_variables_read}),
                "state_writes": sorted({v.canonical_name for v in function.state_variables_written}),
                "external_calls": calls,
                "source": location(function.source_mapping, project),
            })
        contracts.append({
            "name": contract.name,
            "source": location(contract.source_mapping, project),
            "entry_points": sorted(functions, key=lambda item: (item["source"]["file"] if item["source"] else "", item["source"]["lines"][0] if item["source"] and item["source"]["lines"] else 0)),
        })
    contracts.sort(key=lambda item: (item["source"]["file"] if item["source"] else "", item["name"]))
    return {
        "schema_version": "1.0",
        "kind": "structural_inventory",
        "notice": "Call/state edges are candidates for review, not exploit findings. Inherited and internal paths require manual tracing.",
        "project": str(project),
        "contracts": contracts,
        "summary": {
            "contracts": len(contracts),
            "entry_points": sum(len(c["entry_points"]) for c in contracts),
            "state_writing_entry_points": sum(bool(f["state_writes"]) for c in contracts for f in c["entry_points"]),
            "external_call_entry_points": sum(bool(f["external_calls"]) for c in contracts for f in c["entry_points"]),
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("project")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        result = inventory(args.project)
    except Exception as exc:
        print(f"inventory incomplete: {exc}", file=sys.stderr)
        return 2
    target = Path(args.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Inventory: {result['summary']['contracts']} contracts, {result['summary']['entry_points']} entry points -> {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
