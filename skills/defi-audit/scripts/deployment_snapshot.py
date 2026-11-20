#!/usr/bin/env python3
"""Read a pinned EVM deployment snapshot through a bounded HTTPS JSON-RPC API.

Only eth_chainId, eth_getBlockByNumber, eth_getCode and eth_getStorageAt are used.
The RPC URL is read from an environment variable and is never logged or saved.
Slot hints are observations, not proof that an address is an ERC-1967 proxy.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


EIP1967_URL = "https://eips.ethereum.org/EIPS/eip-1967"
# EIP-1967 specification, keccak256("eip1967.proxy.<name>") - 1.
SLOTS = {
    "implementation": "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
    "admin": "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103",
    "beacon": "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50",
}
ALLOWED_METHODS = frozenset({"eth_chainId", "eth_getBlockByNumber", "eth_getCode", "eth_getStorageAt"})
ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}\Z")
HEX = re.compile(r"0x[0-9a-fA-F]*\Z")
HASH32 = re.compile(r"0x[0-9a-fA-F]{64}\Z")
MAX_ADDRESSES = 32
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_CODE_BYTES = 256 * 1024
DEFAULT_TIMEOUT_SECONDS = 10


class SnapshotError(ValueError):
    """Invalid input or untrusted RPC response; safe to show without credentials."""


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        # A key-bearing HTTPS RPC endpoint must never follow a redirect to HTTP
        # or an unrelated HTTPS host. The 3xx status is reported without newurl.
        return None


def _open_https(request: Request, timeout: int):
    return build_opener(_NoRedirect()).open(request, timeout=timeout)


def _validate_rpc_url(raw: str) -> str:
    try:
        parsed = urlsplit(raw)
        valid = (parsed.scheme == "https" and bool(parsed.hostname)
                 and parsed.username is None and parsed.password is None
                 and not parsed.fragment)
    except ValueError:
        valid = False
    if not valid:
        raise SnapshotError("RPC endpoint must be an HTTPS URL without embedded credentials or fragment")
    return raw


def validate_addresses(raw: list[str]) -> list[str]:
    if not raw or len(raw) > MAX_ADDRESSES:
        raise SnapshotError(f"provide 1 to {MAX_ADDRESSES} explicit contract addresses")
    addresses = []
    seen = set()
    for value in raw:
        if not ADDRESS.fullmatch(value):
            raise SnapshotError("each address must be 0x followed by 40 hexadecimal characters")
        address = value.lower()
        if address in seen:
            raise SnapshotError("duplicate contract address")
        seen.add(address)
        addresses.append(address)
    return addresses


def _hex_quantity(value: str, label: str) -> int:
    if not isinstance(value, str) or not re.fullmatch(r"0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)", value):
        raise SnapshotError(f"invalid {label} quantity in RPC response")
    return int(value, 16)


class ReadOnlyRPC:
    def __init__(self, url: str, timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS):
        self.url = _validate_rpc_url(url)
        if not 1 <= timeout_seconds <= 60:
            raise SnapshotError("RPC timeout must be 1 to 60 seconds")
        self.timeout_seconds = timeout_seconds
        self._id = 0
        self.methods_used: list[str] = []

    def call(self, method: str, params: list) -> object:
        if method not in ALLOWED_METHODS:
            raise SnapshotError("RPC method is not on the read-only allowlist")
        self._id += 1
        request_id = self._id
        payload = json.dumps({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}).encode()
        request = Request(self.url, data=payload, headers={"Content-Type": "application/json"}, method="POST")
        try:
            with _open_https(request, timeout=self.timeout_seconds) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
        except HTTPError as exc:
            # HTTPError/URLError strings may include API-key-bearing URLs.
            raise SnapshotError(f"RPC HTTP error {exc.code}") from None
        except (URLError, TimeoutError, OSError, ValueError):
            raise SnapshotError("RPC transport failed or timed out") from None
        if len(raw) > MAX_RESPONSE_BYTES:
            raise SnapshotError("RPC response exceeded the byte limit")
        try:
            envelope = json.loads(raw)
        except (UnicodeError, json.JSONDecodeError):
            raise SnapshotError("RPC returned invalid JSON") from None
        if not isinstance(envelope, dict) or envelope.get("jsonrpc") != "2.0" or envelope.get("id") != request_id:
            raise SnapshotError("RPC returned an invalid JSON-RPC envelope")
        if "error" in envelope:
            # RPC error messages are untrusted and may echo the endpoint/secret.
            raise SnapshotError(f"RPC method {method} returned an error")
        if "result" not in envelope:
            raise SnapshotError("RPC returned no result")
        self.methods_used.append(method)
        return envelope["result"]


def _storage_address(raw: object) -> tuple[str, str | None]:
    if not isinstance(raw, str) or not HASH32.fullmatch(raw):
        raise SnapshotError("RPC returned malformed 32-byte storage value")
    word = raw.lower()
    if int(word, 16) == 0:
        return word, None
    # EIP-1967 address slots are ABI-like right-aligned 20-byte addresses.
    if int(word[2:26], 16) != 0:
        return word, None
    return word, "0x" + word[-40:]


def _code_summary(raw: object) -> tuple[int, str]:
    if not isinstance(raw, str) or not HEX.fullmatch(raw) or (len(raw) - 2) % 2:
        raise SnapshotError("RPC returned malformed code hex")
    if (len(raw) - 2) // 2 > MAX_CODE_BYTES:
        raise SnapshotError("RPC returned code exceeding the byte limit")
    code = bytes.fromhex(raw[2:])
    return len(code), hashlib.sha256(code).hexdigest()


def snapshot(rpc: ReadOnlyRPC, *, chain_id: int, block_number: int, addresses: list[str]) -> dict:
    if chain_id <= 0 or block_number < 0:
        raise SnapshotError("chain ID must be positive and block number nonnegative")
    addresses = validate_addresses(addresses)
    observed_chain = _hex_quantity(rpc.call("eth_chainId", []), "chain ID")
    if observed_chain != chain_id:
        raise SnapshotError(f"RPC chain ID mismatch: expected {chain_id}, observed {observed_chain}")
    block_tag = hex(block_number)
    block = rpc.call("eth_getBlockByNumber", [block_tag, False])
    if not isinstance(block, dict) or _hex_quantity(block.get("number"), "block number") != block_number:
        raise SnapshotError("RPC did not return the requested pinned block")
    block_hash = block.get("hash")
    if not isinstance(block_hash, str) or not HASH32.fullmatch(block_hash):
        raise SnapshotError("RPC returned no canonical block hash")
    entries = []
    for address in addresses:
        code_len, code_hash = _code_summary(rpc.call("eth_getCode", [address, block_tag]))
        slots = {}
        for name, slot in SLOTS.items():
            word, decoded = _storage_address(rpc.call("eth_getStorageAt", [address, slot, block_tag]))
            slots[name] = {"slot": slot, "raw": word, "address": decoded}
        entries.append({
            "address": address, "code_bytes": code_len, "code_sha256": code_hash,
            "code_empty": code_len == 0, "erc1967_slots": slots,
        })
    # Number-based JSON-RPC calls can straddle a reorg. Confirm that the same
    # numbered block still has the original hash after all code/storage reads.
    final_block = rpc.call("eth_getBlockByNumber", [block_tag, False])
    final_hash = final_block.get("hash") if isinstance(final_block, dict) else None
    if (not isinstance(final_block, dict)
            or _hex_quantity(final_block.get("number"), "final block number") != block_number
            or not isinstance(final_hash, str) or not HASH32.fullmatch(final_hash)
            or final_hash.lower() != block_hash.lower()):
        raise SnapshotError("pinned block changed during snapshot; discard mixed-state result")
    return {
        "schema_version": "1.0", "kind": "read_only_deployment_snapshot",
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "chain_id": chain_id, "block_number": block_number, "block_hash": block_hash.lower(),
        "addresses": entries, "rpc_methods_used": sorted(set(rpc.methods_used)),
        "slot_specification": EIP1967_URL,
        "limitations": [
            "ERC-1967 slot values are hints; proxy behavior and implementation bytecode are not verified by this snapshot.",
            "Only explicitly supplied addresses were queried. No beacon implementation() call or other address was followed.",
        ],
    }


def write_snapshot(path: Path, data: dict) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    sidecar = path.with_name(path.name + ".sha256")
    if path.exists() or sidecar.exists():
        raise SnapshotError("snapshot output already exists; choose a new evidence path")
    blob = (json.dumps(data, indent=2, sort_keys=True) + "\n").encode("utf-8")
    temporary = None
    try:
        with tempfile.NamedTemporaryFile("wb", dir=path.parent, prefix=".deployment-snapshot-", suffix=".tmp", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(blob)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    digest = hashlib.sha256(blob).hexdigest()
    sidecar.write_text(f"{digest}  {path.name}\n", encoding="ascii")
    return digest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rpc-env", default="RPC_URL", help="name of environment variable containing HTTPS RPC URL")
    parser.add_argument("--expected-chain-id", type=int, required=True)
    parser.add_argument("--block", type=int, required=True, help="fixed block number")
    parser.add_argument("--address", action="append", required=True, help="explicit scoped contract address; repeatable")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=DEFAULT_TIMEOUT_SECONDS)
    args = parser.parse_args(argv)
    try:
        if not ENV_NAME.fullmatch(args.rpc_env):
            raise SnapshotError("invalid RPC environment variable name")
        url = os.environ.get(args.rpc_env)
        if not url:
            raise SnapshotError(f"RPC environment variable {args.rpc_env} is unset")
        rpc = ReadOnlyRPC(url, args.timeout_seconds)
        result = snapshot(rpc, chain_id=args.expected_chain_id, block_number=args.block,
                          addresses=args.address)
        digest = write_snapshot(args.output, result)
        print(f"wrote {args.output} sha256={digest}; {len(result['addresses'])} explicit address(es) at chain {result['chain_id']} block {result['block_number']}")
        return 0
    except SnapshotError as exc:
        print(f"deployment snapshot error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
