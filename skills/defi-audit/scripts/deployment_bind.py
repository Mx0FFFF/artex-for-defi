#!/usr/bin/env python3
"""Bind one passing local test source snapshot to exact pinned EVM runtime code.

Sourcify's exact runtime match is an external verification statement. This
adapter independently compares its reported onchain bytes to the pinned RPC
snapshot and its source files to the test run's retained source archive. It
does not prove that the local test models every deployed dependency or state.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Any


HASH = re.compile(r"[0-9a-f]{64}\Z")
BLOCK_HASH = re.compile(r"0x[0-9a-fA-F]{64}\Z")
ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}\Z")
HEX_BYTES = re.compile(r"0x(?:[0-9a-fA-F]{2})*\Z")
MAX_JSON = 20 << 20
MAX_CODE = 256 << 10
MAX_SOURCE = 5 << 20
MAX_SOURCES = 1000
MAX_ARCHIVE = 1536 << 20


class BindingError(ValueError):
    """The deployment identity cannot be established from these artifacts."""


def file_hash(path: Path, max_bytes: int) -> str:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > max_bytes:
        raise BindingError(f"missing, linked or oversized artifact: {path.name}")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path: Path, max_bytes: int = 2 << 20) -> dict[str, Any]:
    file_hash(path, max_bytes)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise BindingError(f"invalid JSON artifact: {path.name}") from exc
    if not isinstance(value, dict):
        raise BindingError(f"JSON artifact must be an object: {path.name}")
    return value


def safe_name(raw: str) -> str:
    if not isinstance(raw, str) or not raw or len(raw) > 1024 or "\\" in raw or "\x00" in raw or raw.startswith("/"):
        raise BindingError("unsafe source/archive path")
    if any(part in {"", ".", ".."} for part in raw.split("/")):
        raise BindingError("unsafe source/archive path")
    return raw


def _ref(path: Path, root: Path, max_bytes: int = MAX_ARCHIVE) -> str:
    try:
        relative = path.resolve(strict=True).relative_to(root.resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise BindingError("artifact is outside the test run") from exc
    if path.is_symlink():
        raise BindingError("linked artifacts are not accepted")
    return safe_name(relative.as_posix()) + "#sha256=" + file_hash(path, max_bytes)


def _write_once(path: Path, blob: bytes) -> None:
    temporary = None
    try:
        with tempfile.NamedTemporaryFile("wb", dir=path.parent, prefix=".deployment-binding-", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(blob)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.chmod(0o600)
        os.link(temporary, path)  # no overwrite, even if another worker raced us
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def resolve_ref(ref: str, root: Path, max_bytes: int = MAX_ARCHIVE) -> Path:
    name, sep, digest = ref.partition("#sha256=")
    if not sep or not HASH.fullmatch(digest):
        raise BindingError("artifact reference must include a lowercase SHA-256")
    path = root.joinpath(*safe_name(name).split("/"))
    cursor = root
    for part in name.split("/"):
        cursor /= part
        if cursor.is_symlink():
            raise BindingError("linked artifact path is not accepted")
    if file_hash(path, max_bytes) != digest:
        raise BindingError("artifact SHA-256 mismatch")
    return path


def _copy_into_run(source: Path, root: Path, label: str, max_bytes: int) -> str:
    digest = file_hash(source, max_bytes)
    target = root / f"{label}-{digest[:16]}.json"
    if target.exists():
        if file_hash(target, max_bytes) != digest:
            raise BindingError("existing copied artifact differs")
    else:
        _write_once(target, source.read_bytes())
        if file_hash(target, max_bytes) != digest:
            target.unlink(missing_ok=True)
            raise BindingError("copied artifact changed")
    return _ref(target, root, max_bytes)


def _source_prefix(raw: str) -> str:
    if raw == "":
        return ""
    return safe_name(raw.rstrip("/")) + "/"


def verify_inputs(result_path: Path, snapshot_path: Path, response_path: Path,
                  source_prefix: str = "") -> dict[str, Any]:
    root = result_path.resolve(strict=True).parent
    if result_path.name != "result.json":
        raise BindingError("test result must be result.json")
    result = read_json(result_path)
    if (result.get("action"), result.get("status"), result.get("exit_code"), result.get("source_drift")) != ("forge-test", "pass", 0, False):
        raise BindingError("deployment binding requires a clean passing forge-test run")
    manifest_path = root / "manifest.json"
    manifest = read_json(manifest_path)
    manifest_hash = file_hash(manifest_path, 2 << 20)
    manifest_location = result.get("manifest")
    if (result.get("manifest_sha256") != manifest_hash or not isinstance(manifest_location, str)
            or Path(manifest_location).resolve() != manifest_path):
        raise BindingError("test result does not bind the retained manifest")
    archive_path = root / "source_snapshot.tar"
    archive_hash = file_hash(archive_path, MAX_ARCHIVE)
    environment = manifest.get("environment")
    source_snapshot = manifest.get("source_snapshot")
    if not isinstance(environment, dict) or not isinstance(source_snapshot, dict):
        raise BindingError("test manifest lacks source identity")
    identity = environment.get("code_identity")
    if identity != {"kind": "source_archive_sha256", "digest": archive_hash}:
        raise BindingError("test manifest does not bind the source archive")
    if source_snapshot.get("sha256") != archive_hash:
        raise BindingError("source snapshot hash differs from manifest")
    snapshot = read_json(snapshot_path)
    if snapshot.get("kind") != "read_only_deployment_snapshot" or snapshot.get("schema_version") != "1.0":
        raise BindingError("not a deployment snapshot")
    chain = snapshot.get("chain_id")
    block = snapshot.get("block_number")
    block_hash = snapshot.get("block_hash")
    if (type(chain) is not int or chain <= 0 or type(block) is not int or block < 0
            or not isinstance(block_hash, str) or not BLOCK_HASH.fullmatch(block_hash)):
        raise BindingError("snapshot chain/block identity is malformed")
    entries = snapshot.get("addresses")
    if not isinstance(entries, list) or len(entries) != 1 or not isinstance(entries[0], dict):
        raise BindingError("snapshot must name exactly one explicit address")
    entry = entries[0]
    address = entry.get("address")
    code_hash = entry.get("code_sha256")
    if (not isinstance(address, str) or not ADDRESS.fullmatch(address)
            or not isinstance(code_hash, str) or not HASH.fullmatch(code_hash)
            or entry.get("code_empty") is not False or type(entry.get("code_bytes")) is not int
            or not 0 < entry["code_bytes"] <= MAX_CODE):
        raise BindingError("snapshot runtime code identity is malformed or empty")
    context = manifest.get("target_context")
    if not isinstance(context, dict) or (context.get("chain_id"), context.get("block_number"), context.get("address")) != (chain, block, address.lower()):
        raise BindingError("test manifest target differs from pinned deployment")
    response = read_json(response_path, MAX_JSON)
    if str(response.get("chainId")) != str(chain) or str(response.get("address", "")).lower() != address.lower():
        raise BindingError("verified source response targets another contract")
    if response.get("runtimeMatch") != "exact_match":
        raise BindingError("Sourcify runtime match is not exact")
    runtime = response.get("runtimeBytecode")
    bytecode = runtime.get("onchainBytecode") if isinstance(runtime, dict) else None
    if not isinstance(bytecode, str) or not HEX_BYTES.fullmatch(bytecode) or not 0 < (len(bytecode)-2)//2 <= MAX_CODE:
        raise BindingError("Sourcify runtime bytecode is missing or malformed")
    observed_hash = hashlib.sha256(bytes.fromhex(bytecode[2:])).hexdigest()
    if observed_hash != code_hash or (len(bytecode)-2)//2 != entry["code_bytes"]:
        raise BindingError("Sourcify runtime bytes differ from pinned onchain code")
    sources = response.get("sources")
    if not isinstance(sources, dict) or not 1 <= len(sources) <= MAX_SOURCES:
        raise BindingError("Sourcify response has no bounded source set")
    prefix = _source_prefix(source_prefix)
    try:
        with tarfile.open(archive_path, "r:") as archive:
            members = archive.getmembers()
            if len(members) > 20_000 or len({member.name for member in members}) != len(members):
                raise BindingError("source archive has too many or duplicate entries")
            by_name = {member.name: member for member in members}
            for name, item in sources.items():
                if not isinstance(item, dict) or not isinstance(item.get("content"), str):
                    raise BindingError("Sourcify source content is missing")
                expected = item["content"].encode("utf-8")
                if len(expected) > MAX_SOURCE:
                    raise BindingError("Sourcify source exceeds size limit")
                mapped = prefix + safe_name(name)
                member = by_name.get(mapped)
                if member is None or not member.isfile() or member.size != len(expected):
                    raise BindingError(f"verified source is missing from test snapshot: {mapped}")
                stream = archive.extractfile(member)
                if stream is None or stream.read(MAX_SOURCE + 1) != expected:
                    raise BindingError(f"verified source differs from test snapshot: {mapped}")
    except (tarfile.TarError, OSError) as exc:
        raise BindingError("source archive could not be checked") from exc
    return {
        "chain_id": chain, "block_number": block, "block_hash": block_hash.lower(),
        "address": address.lower(), "runtime_code_sha256": code_hash,
        "source_archive_sha256": archive_hash, "run_manifest_sha256": manifest_hash,
        "matched_source_count": len(sources), "source_prefix": prefix,
    }


def bind(result_path: Path, snapshot_path: Path, response_path: Path,
         output_path: Path, source_prefix: str = "") -> dict[str, Any]:
    root = result_path.resolve(strict=True).parent
    if output_path.resolve() != root / "deployment_binding.json" or output_path.exists():
        raise BindingError("binding output must be a new deployment_binding.json beside result.json")
    summary = verify_inputs(result_path, snapshot_path, response_path, source_prefix)
    snapshot_ref = _copy_into_run(snapshot_path, root, "deployment_snapshot", 2 << 20)
    response_ref = _copy_into_run(response_path, root, "sourcify_response", MAX_JSON)
    binding = {
        "schema_version": "1.0", "kind": "exact_deployment_source_binding",
        **summary,
        "result_ref": _ref(result_path, root, 2 << 20),
        "manifest_ref": _ref(root / "manifest.json", root, 2 << 20),
        "source_archive_ref": _ref(root / "source_snapshot.tar", root),
        "snapshot_ref": snapshot_ref, "sourcify_response_ref": response_ref,
        "limitations": ["Exact runtime/source identity does not establish exploit reachability or fork state fidelity."],
    }
    _write_once(output_path, (json.dumps(binding, indent=2, sort_keys=True) + "\n").encode())
    return binding


def verify_binding(root: Path, binding: dict[str, Any]) -> dict[str, Any]:
    if binding.get("kind") != "exact_deployment_source_binding" or binding.get("schema_version") != "1.0":
        raise BindingError("not an exact deployment source binding")
    refs = {key: binding.get(key) for key in ("result_ref", "manifest_ref", "source_archive_ref", "snapshot_ref", "sourcify_response_ref")}
    if any(not isinstance(ref, str) for ref in refs.values()):
        raise BindingError("deployment binding lacks hashed artifacts")
    if not isinstance(binding.get("source_prefix"), str):
        raise BindingError("deployment binding source prefix is malformed")
    limits = {"result_ref": 2 << 20, "manifest_ref": 2 << 20,
              "source_archive_ref": MAX_ARCHIVE, "snapshot_ref": 2 << 20,
              "sourcify_response_ref": MAX_JSON}
    paths = {key: resolve_ref(ref, root, limits[key]) for key, ref in refs.items()}
    if paths["result_ref"].name != "result.json" or paths["manifest_ref"].name != "manifest.json" or paths["source_archive_ref"].name != "source_snapshot.tar":
        raise BindingError("deployment binding references unexpected run files")
    summary = verify_inputs(paths["result_ref"], paths["snapshot_ref"], paths["sourcify_response_ref"], binding.get("source_prefix", ""))
    for key, value in summary.items():
        if binding.get(key) != value:
            raise BindingError(f"deployment binding {key} differs from its artifacts")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--sourcify-response", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-prefix", default="")
    args = parser.parse_args()
    try:
        binding = bind(args.result, args.snapshot, args.sourcify_response,
                       args.output, args.source_prefix)
        print(json.dumps({"binding": str(args.output), "chain_id": binding["chain_id"],
                          "block_number": binding["block_number"], "address": binding["address"]}))
        return 0
    except (BindingError, OSError, ValueError) as exc:
        print(f"deployment binding blocked: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
