#!/usr/bin/env python3
"""Fetch one verified EVM contract's sources from Sourcify API v2 (read-only)."""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path, PurePosixPath
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}\Z")
MAX_RESPONSE = 20 * 1024 * 1024
MAX_SOURCE = 5 * 1024 * 1024
MAX_CODE = 256 * 1024


def safe_source_path(root: Path, name: str) -> Path:
    """Reject absolute, traversing, and Windows-style paths from remote metadata."""
    if not name or len(name) > 1024 or "\\" in name or name.startswith("/") or any(part in ("", ".", "..") for part in name.split("/")):
        raise ValueError(f"unsafe source path: {name!r}")
    rel = PurePosixPath(name)
    if rel.is_absolute() or any(part in ("", ".", "..") for part in rel.parts):
        raise ValueError(f"unsafe source path: {name!r}")
    target = (root / Path(*rel.parts)).resolve()
    if not target.is_relative_to(root.resolve()):
        raise ValueError(f"unsafe source path: {name!r}")
    return target


def fetch(chain_id: int, address: str) -> dict:
    url = (
        "https://sourcify.dev/server/v2/contract/"
        f"{chain_id}/{address}?fields=sources,compilation,proxyResolution,runtimeBytecode.onchainBytecode"
    )
    req = Request(
        url,
        headers={
            "User-Agent": "ARTEX-defi-audit/1.0 (+https://github.com/mhtsec/ARTEX)",
            "Accept": "application/json",
        },
    )
    with urlopen(req, timeout=30) as response:
        raw = response.read(MAX_RESPONSE + 1)
    if len(raw) > MAX_RESPONSE:
        raise ValueError("Sourcify response exceeds 20 MiB")
    return json.loads(raw)


def save_sources(data: dict, root: Path) -> int:
    sources = data.get("sources")
    if not isinstance(sources, dict) or not sources:
        raise ValueError("No verified source files in Sourcify response")
    if len(sources) > 1000:
        raise ValueError("Too many source files")
    planned = []
    for name, entry in sources.items():
        content = entry.get("content") if isinstance(entry, dict) else None
        if not isinstance(content, str):
            raise ValueError(f"Source lacks text content: {name!r}")
        blob = content.encode("utf-8")
        if len(blob) > MAX_SOURCE:
            raise ValueError(f"Source exceeds 5 MiB: {name!r}")
        planned.append((safe_source_path(root, name), blob))
    for path, blob in planned:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(blob)
    return len(planned)


def runtime_code_hash(data: dict) -> str | None:
    runtime = data.get("runtimeBytecode")
    raw = runtime.get("onchainBytecode") if isinstance(runtime, dict) else None
    if raw is None:
        return None
    if not isinstance(raw, str) or not re.fullmatch(r"0x(?:[0-9a-fA-F]{2})*", raw) or (len(raw)-2)//2 > MAX_CODE:
        raise ValueError("Sourcify runtime bytecode is malformed or oversized")
    return hashlib.sha256(bytes.fromhex(raw[2:])).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("chain_id", type=int)
    parser.add_argument("address")
    parser.add_argument("output_dir", type=Path)
    args = parser.parse_args()
    if args.chain_id <= 0 or not ADDRESS.fullmatch(args.address):
        parser.error("supply a positive EVM chain ID and a 0x-prefixed 40-hex address")
    root = args.output_dir / f"{args.chain_id}-{args.address.lower()}"
    root.mkdir(parents=True, exist_ok=True)
    cache = root / "sourcify-response.json"
    try:
        data = json.loads(cache.read_text()) if cache.exists() else fetch(args.chain_id, args.address)
        if not isinstance(data, dict):
            raise ValueError("Sourcify response must be a JSON object")
        if cache.exists() and not isinstance(data.get("runtimeBytecode"), dict):
            data = fetch(args.chain_id, args.address)
        if not isinstance(data, dict):
            raise ValueError("Sourcify response must be a JSON object")
        if str(data.get("chainId")) != str(args.chain_id) or str(data.get("address", "")).lower() != args.address.lower():
            raise ValueError("Sourcify response chain/address does not match requested target")
        code_hash = runtime_code_hash(data)
        if data.get("runtimeMatch") == "exact_match" and code_hash is None:
            raise ValueError("Sourcify exact runtime match lacks runtime bytecode")
        count = save_sources(data, root / "sources")
        cache.write_text(json.dumps(data, indent=2), encoding="utf-8")
        compilation = data.get("compilation")
        if not isinstance(compilation, dict):
            compilation = {}
        manifest = {
            "chain_id": args.chain_id,
            "address": args.address.lower(),
            "source_count": count,
            "match": data.get("match"),
            "runtime_match": data.get("runtimeMatch"),
            "runtime_code_sha256": code_hash,
            "compiler": compilation.get("compilerVersion"),
            "proxy_resolution": data.get("proxyResolution"),
        }
        (root / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        print(f"Saved {count} verified files in {root / 'sources'}")
        print(f"Match: {manifest['match']}; runtime match: {manifest['runtime_match']}; compiler: {manifest['compiler']}")
        return 0
    except (HTTPError, URLError, ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"Source lookup failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
