#!/usr/bin/env python3
"""Record reproducible, bounded local analysis of a Foundry project.

This wrapper deliberately exposes only three fixed actions. It does not install
dependencies, use a shell, accept an RPC URL, or broadcast transactions. A
repository's build and tests can still execute untrusted code or Foundry hooks;
run untrusted repositories in an external sandbox with no credentials. Snapshot
archives may contain source-embedded secrets; keep output directories private.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import selectors
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import time
import tomllib
import uuid
from datetime import datetime, timezone
from pathlib import Path


MAX_TIMEOUT_SECONDS = 3600
DEFAULT_TIMEOUT_SECONDS = 600
MAX_OUTPUT_BYTES = 64 * 1024 * 1024
DEFAULT_OUTPUT_BYTES = 8 * 1024 * 1024
MAX_SOURCE_FILES = 20_000
MAX_SOURCE_BYTES = 1024 * 1024 * 1024
MAX_SINGLE_SOURCE_BYTES = 64 * 1024 * 1024
GENERATED_FOUNDRY_DIRS = frozenset({"out", "cache", "broadcast"})
SENSITIVE_SUFFIXES = frozenset({".key", ".pem", ".p12", ".pfx", ".keystore"})
SOLIDITY_IMPORT_RE = re.compile(r"\bimport\s+(?:\{[^}]*\}\s+from\s+|\*\s+as\s+\w+\s+from\s+)?[\"']([^\"']+)[\"']", re.S)
VYPER_IMPORT_RE = re.compile(r"(?m)^\s*(?:from\s+([\w.]+)\s+import|import\s+([\w.]+))")
EVM_ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}\Z")
SAFE_FOUNDRY_KEYS = frozenset({
    "src", "test", "script", "out", "libs", "solc", "solc_version",
    "evm_version", "optimizer", "optimizer_runs", "via_ir", "bytecode_hash",
    "auto_detect_solc", "ffi",
})
SAFE_FUZZ_KEYS = frozenset({"runs", "max_test_rejects", "depth", "fail_on_revert", "dictionary_weight", "seed"})
VERSION_COMMANDS = {
    "forge": ["forge", "--version"],
    "slither": ["slither", "--version"],
    "solc": ["solc", "--version"],
    "halmos": ["halmos", "--version"],
}

# The currently-running heavy child (forge/slither/solc). It runs in its own
# session, so an external termination signal to this process must reap it
# explicitly or it is orphaned. See install_termination_handlers.
_ACTIVE_CHILD: "subprocess.Popen | None" = None


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(path.name + ".tmp-" + uuid.uuid4().hex[:8])
    try:
        temporary.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
        temporary.chmod(0o600)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def safe_environment() -> dict[str, str]:
    # In particular, do not pass LLM/API keys or RPC credentials into an
    # untrusted repository's build and tests. This is not a process sandbox.
    allowed = {
        "PATH", "HOME", "TMPDIR", "TEMP", "TMP", "USER", "LANG", "LC_ALL",
        "XDG_CACHE_HOME", "XDG_CONFIG_HOME", "FOUNDRY_PROFILE", "FOUNDRY_SOLC",
        "SOLC_VERSION", "SOLC_BIN", "PYTHONHOME",
    }
    env = {key: value for key, value in os.environ.items() if key in allowed}
    env.update({"FOUNDRY_OFFLINE": "true", "NO_COLOR": "1"})
    return env


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def is_sensitive_filename(name: str) -> bool:
    lower = name.lower()
    if lower.startswith(".env") and not lower.endswith((".example", ".sample", ".template")):
        return True
    return any(lower.endswith(suffix) for suffix in SENSITIVE_SUFFIXES)


def source_tree_identity(project: Path, output_dir: Path, action: str | None = None) -> tuple[dict, list[Path]]:
    """Hash all project inputs; exclude only confirmed Foundry outputs.

    The source snapshot is intentionally bounded. Large dependency trees fail
    closed rather than silently disappearing from provenance.
    """
    digest = hashlib.sha256()
    file_count = 0
    total_bytes = 0
    symlink_count = 0
    entries: list[Path] = []
    excluded_dirs = {".git"}
    if action != "slither":
        excluded_dirs.update(GENERATED_FOUNDRY_DIRS)
    output_inside = output_dir == project or project in output_dir.parents
    output_rel = output_dir.relative_to(project) if output_inside else None
    for root_text, dirs, files in os.walk(project, topdown=True, followlinks=False):
        root = Path(root_text)
        dirs[:] = sorted(d for d in dirs if d != ".git" and not (root == project and d in excluded_dirs))
        if output_rel is not None:
            dirs[:] = [d for d in dirs if root / d != project / output_rel]
        symlink_dirs = [d for d in dirs if (root / d).is_symlink()]
        dirs[:] = [d for d in dirs if d not in symlink_dirs]
        for name in symlink_dirs:
            path = root / name
            rel = path.relative_to(project).as_posix()
            file_count += 1
            symlink_count += 1
            if file_count > MAX_SOURCE_FILES:
                raise ValueError(f"source file limit exceeded ({MAX_SOURCE_FILES})")
            value = os.readlink(path).encode("utf-8", errors="surrogateescape")
            digest.update(b"symlink\0" + rel.encode("utf-8", errors="surrogateescape") + b"\0" + value + b"\0")
            entries.append(path)
        for name in sorted(files):
            path = root / name
            rel = path.relative_to(project).as_posix()
            if is_sensitive_filename(name):
                raise ValueError(f"project contains a secret-like file ({rel}); analyze a sanitized checkout")
            if output_rel is not None and path == project / output_rel:
                continue
            file_count += 1
            if file_count > MAX_SOURCE_FILES:
                raise ValueError(f"source file limit exceeded ({MAX_SOURCE_FILES})")
            if path.is_symlink():
                symlink_count += 1
                entries.append(path)
                value = os.readlink(path).encode("utf-8", errors="surrogateescape")
                digest.update(b"symlink\0" + rel.encode("utf-8", errors="surrogateescape") + b"\0" + value + b"\0")
                continue
            file_stat = path.stat()
            if not stat.S_ISREG(file_stat.st_mode):
                raise ValueError(f"source tree contains a non-regular file: {rel}")
            size = file_stat.st_size
            if size > MAX_SINGLE_SOURCE_BYTES:
                raise ValueError(f"source file exceeds {MAX_SINGLE_SOURCE_BYTES} bytes: {rel}")
            total_bytes += size
            if total_bytes > MAX_SOURCE_BYTES:
                raise ValueError(f"source tree exceeds {MAX_SOURCE_BYTES} bytes")
            digest.update(b"file\0" + rel.encode("utf-8", errors="surrogateescape") + b"\0")
            digest.update(str(size).encode("ascii") + b"\0")
            digest.update(file_sha256(path).encode("ascii") + b"\0")
            entries.append(path)
    if action != "slither":
        validate_excluded_imports(project, entries, excluded_dirs - {".git"})
    return {
        "source_tree_sha256": digest.hexdigest(),
        "source_file_count": file_count,
        "source_bytes": total_bytes,
        "symlink_count": symlink_count,
        "source_tree_hash_exclusions": [".git/**"] + ([name + "/**" for name in sorted(excluded_dirs - {".git"})]) + ([str(output_rel) + "/**"] if output_rel is not None else []),
    }, entries


def validate_excluded_imports(project: Path, entries: list[Path], excluded: set[str]) -> None:
    """Fail if a claimed generated-output exclusion can be a compiler input."""
    def targets_excluded(value: str, source: Path | None = None) -> bool:
        raw = value.replace("\\", "/").strip()
        parts = [part for part in raw.split("/") if part not in {"", "."}]
        if parts and parts[0] in excluded:
            return True
        if source is not None and Path(raw).is_absolute():
            resolved = Path(raw).resolve()
            if project in resolved.parents:
                relative = resolved.relative_to(project)
                return bool(relative.parts and relative.parts[0] in excluded)
        if source is not None and raw.startswith("."):
            resolved = (source.parent / raw).resolve()
            if project in resolved.parents:
                relative = resolved.relative_to(project)
                return bool(relative.parts and relative.parts[0] in excluded)
        return False

    for source in entries:
        if source.is_symlink() or source.suffix not in {".sol", ".vy", ".yul"}:
            continue
        content = source.read_text(encoding="utf-8", errors="replace")
        imports = [match.group(1) for match in SOLIDITY_IMPORT_RE.finditer(content)]
        if source.suffix == ".vy":
            imports.extend((match.group(1) or match.group(2)).replace(".", "/") for match in VYPER_IMPORT_RE.finditer(content))
        if any(targets_excluded(value, source) for value in imports):
            raise ValueError(f"source imports an excluded generated directory: {source.relative_to(project)}")

    config_path = project / "foundry.toml"
    if config_path.is_file():
        parsed = tomllib.loads(config_path.read_text(encoding="utf-8"))
        profiles = parsed.get("profile", {})
        selected = profiles.get(os.environ.get("FOUNDRY_PROFILE", "default"), {}) if isinstance(profiles, dict) else {}
        if isinstance(selected, dict):
            for key in ("src", "test", "script", "out", "libs", "remappings", "include_paths"):
                values = selected.get(key, [])
                if isinstance(values, str):
                    values = [values]
                if isinstance(values, list):
                    for value in values:
                        if isinstance(value, str) and targets_excluded(value.split("=", 1)[-1]):
                            # `out=out` is an output designation, not an import.
                            if key != "out":
                                raise ValueError(f"foundry.toml {key} references an excluded generated directory")
    remappings = project / "remappings.txt"
    if remappings.is_file():
        for line in remappings.read_text(encoding="utf-8", errors="replace").splitlines():
            if "=" in line and targets_excluded(line.split("=", 1)[1]):
                raise ValueError("remappings.txt references an excluded generated directory")


def write_source_archive(project: Path, entries: list[Path], path: Path) -> dict:
    """Store a deterministic snapshot, with no host timestamps or ownership."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        with tarfile.open(path, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for source in sorted(entries, key=lambda item: item.relative_to(project).as_posix()):
                relative = source.relative_to(project).as_posix()
                info = tarfile.TarInfo(relative)
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                info.mtime = 0
                if source.is_symlink():
                    target = os.readlink(source)
                    # Do not claim a complete snapshot when a link depends on
                    # content outside the scoped project.
                    resolved = (source.parent / target).resolve()
                    if project not in resolved.parents and resolved != project:
                        raise ValueError(f"source symlink points outside project: {relative}")
                    info.type = tarfile.SYMTYPE
                    info.linkname = target
                    info.mode = 0o777
                    archive.addfile(info)
                    continue
                stat = source.stat()
                info.type = tarfile.REGTYPE
                info.size = stat.st_size
                info.mode = 0o755 if stat.st_mode & 0o111 else 0o644
                with source.open("rb") as content:
                    archive.addfile(info, content)
        path.chmod(0o600)
    except Exception:
        path.unlink(missing_ok=True)
        raise
    return {"path": path.name, "sha256": file_sha256(path), "bytes": path.stat().st_size}


def git_commit(project: Path) -> str | None:
    try:
        completed = subprocess.run(
            ["git", "-C", str(project), "rev-parse", "--verify", "HEAD"],
            capture_output=True, text=True, timeout=5, check=False, env=safe_environment(),
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    commit = completed.stdout.strip()
    return commit if completed.returncode == 0 and re.fullmatch(r"[0-9a-fA-F]{40,64}", commit) else None


def tool_version(name: str) -> str | None:
    if shutil.which(name) is None:
        return None
    try:
        completed = subprocess.run(
            VERSION_COMMANDS[name], capture_output=True, timeout=10, check=False,
            env=safe_environment(),
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    raw = (completed.stdout or completed.stderr)[:4096].decode("utf-8", errors="replace").strip()
    if completed.returncode != 0 or not raw:
        return None
    lines = raw.splitlines()
    if name == "solc":
        return next((line.strip() for line in lines if line.startswith("Version:")), lines[0])
    return lines[0]


def foundry_config(project: Path) -> dict:
    path = project / "foundry.toml"
    if not path.is_file():
        return {"present": False}
    raw = path.read_bytes()
    config = tomllib.loads(raw.decode("utf-8"))
    profiles = config.get("profile", {})
    selected_name = os.environ.get("FOUNDRY_PROFILE", "default")
    selected = profiles.get(selected_name, {}) if isinstance(profiles, dict) else {}
    if not isinstance(selected, dict):
        selected = {}
    # Exclude rpc_endpoints, etherscan, fs_permissions, env interpolation,
    # secrets and arbitrary custom fields. The file hash records full provenance.
    safe = {key: selected[key] for key in SAFE_FOUNDRY_KEYS if key in selected}
    for key in ("fuzz", "invariant"):
        nested = selected.get(key)
        if isinstance(nested, dict):
            safe[key] = {field: nested[field] for field in SAFE_FUZZ_KEYS if field in nested}
    return {
        "present": True,
        "foundry_toml_sha256": sha256_bytes(raw),
        "profile": selected_name,
        "compiler_and_test_config": safe,
    }


def build_info_compilers(project: Path, config: dict) -> list[str]:
    """Read the compiler versions actually recorded by Foundry build-info."""
    out_value = config.get("compiler_and_test_config", {}).get("out", "out")
    if not isinstance(out_value, str):
        return []
    out_path = (project / out_value).resolve()
    if project not in out_path.parents and out_path != project:
        raise ValueError("Foundry out directory is outside the project snapshot")
    directory = out_path / "build-info"
    if not directory.is_dir():
        return []
    files = sorted(directory.glob("*.json"))
    if len(files) > 500:
        raise ValueError("too many Foundry build-info files")
    versions: set[str] = set()
    for path in files:
        if path.stat().st_size > 16 * 1024 * 1024:
            raise ValueError("Foundry build-info file exceeds 16 MiB")
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (UnicodeError, ValueError) as exc:
            raise ValueError(f"invalid Foundry build-info: {path.name}") from exc
        version = data.get("solcLongVersion") or data.get("solcVersion")
        if isinstance(version, str) and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[+.-][A-Za-z0-9.+-]+)?", version):
            versions.add(version)
    return sorted(versions)


def configured_compiler(project: Path, config: dict) -> str | None:
    selected = config.get("compiler_and_test_config", {})
    version = selected.get("solc_version") or selected.get("solc")
    if not isinstance(version, str) or not version:
        return None
    if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        return "Solc " + version
    path = (project / version).resolve()
    if path.is_file() and os.access(path, os.X_OK):
        try:
            completed = subprocess.run([str(path), "--version"], capture_output=True, timeout=10,
                                       check=False, env=safe_environment())
            if completed.returncode == 0:
                lines = completed.stdout.decode("utf-8", errors="replace").splitlines()
                actual = next((line.strip() for line in lines if line.startswith("Version:")), None)
                return actual
        except (OSError, subprocess.TimeoutExpired):
            return None
    return None


def compiler_label(versions: list[str]) -> str | None:
    return ", ".join("Solc " + version for version in versions) if versions else None


def effective_foundry_ffi(project: Path) -> bool | None:
    """Read the resolved Forge setting; reject tests unless FFI is disabled."""
    executable = shutil.which("forge")
    if executable is None:
        return None
    try:
        completed = subprocess.run(
            [executable, "config", "--json"], cwd=project, env=safe_environment(),
            capture_output=True, timeout=10, check=False,
        )
        if completed.returncode != 0 or len(completed.stdout) > 1024 * 1024:
            return None
        value = json.loads(completed.stdout).get("ffi")
        return value if isinstance(value, bool) else None
    except (OSError, subprocess.TimeoutExpired, ValueError, AttributeError):
        return None


def validate_context(args: argparse.Namespace) -> dict:
    chain_id, block, address = args.chain_id, args.block_number, args.address
    if chain_id is not None and chain_id <= 0:
        raise ValueError("chain ID must be positive")
    if block is not None and (block < 0 or chain_id is None):
        raise ValueError("block number must be nonnegative and requires chain ID")
    if address is not None and (chain_id is None or EVM_ADDRESS.fullmatch(address) is None):
        raise ValueError("address must be 0x + 40 hex and requires chain ID")
    return {"chain_id": chain_id, "block_number": block, "address": address.lower() if address else None}


def build_manifest(project: Path, output_dir: Path, archive_path: Path, args: argparse.Namespace) -> dict:
    if not project.is_dir():
        raise ValueError(f"project directory does not exist: {project}")
    if project == output_dir:
        raise ValueError("output directory must not equal project directory")
    context = validate_context(args)
    source_action = args.action if args.command == "run" else None
    code, entries = source_tree_identity(project, output_dir, source_action)
    archive = write_source_archive(project, entries, archive_path)
    code_after_archive, _ = source_tree_identity(project, output_dir, source_action)
    if code_after_archive["source_tree_sha256"] != code["source_tree_sha256"]:
        archive_path.unlink(missing_ok=True)
        raise ValueError("source inputs changed while snapshot archive was created")
    commit = git_commit(project)
    versions = {name: version for name in VERSION_COMMANDS if (version := tool_version(name)) is not None}
    config = foundry_config(project)
    build_compilers = build_info_compilers(project, config)
    configured = configured_compiler(project, config)
    compiler = compiler_label(build_compilers) or configured
    resolved_ffi = effective_foundry_ffi(project) if args.command == "run" and args.action == "forge-test" else None
    manifest = {
        "schema_version": 1,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "project_path": str(project),
        "target_context": context,
        "environment": {
            "code_identity": {"kind": "source_archive_sha256", "digest": archive["sha256"]},
            "commit": commit,
            "tool_versions": versions,
            "chain": str(context["chain_id"]) if context["chain_id"] is not None else None,
            "fork_block": context["block_number"],
            "compiler": compiler,
            "execution_engine": "Foundry " + versions["forge"] if "forge" in versions else None,
        },
        "foundry_config": config,
        "compiler_provenance": {"build_info_versions": build_compilers, "configured_compiler": configured},
        "execution_policy": {"offline": True, "forge_test_effective_ffi": resolved_ffi, "live_broadcast": False},
        "source_snapshot": archive,
        **code,
    }
    return manifest


def terminate_process_group(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
    except ProcessLookupError:
        pass


def _terminate_active_child_and_reraise(signum: int, _frame: object) -> None:
    child = _ACTIVE_CHILD
    if child is not None:
        terminate_process_group(child)
    signal.signal(signum, signal.SIG_DFL)
    os.kill(os.getpid(), signum)


def install_termination_handlers() -> None:
    """Reap the detached forge/solc child if the orchestrator cancels this run.

    The heavy child runs in its own session (start_new_session) so a local
    timeout can kill its whole group. That same isolation means an external
    SIGTERM/SIGINT to this process would otherwise leave the compiler running,
    so each handler kills the active child group before re-raising the signal.
    """
    targets = [signal.SIGTERM, signal.SIGINT]
    hangup = getattr(signal, "SIGHUP", None)
    if hangup is not None:
        targets.append(hangup)
    for sig in targets:
        try:
            signal.signal(sig, _terminate_active_child_and_reraise)
        except (OSError, ValueError):
            pass


def bounded_execute(argv: list[str], project: Path, run_dir: Path, timeout: int, max_output: int, prefix: str = "") -> dict:
    global _ACTIVE_CHILD
    stdout_path = run_dir / (prefix + "stdout.log")
    stderr_path = run_dir / (prefix + "stderr.log")
    timed_out = False
    output_limited = False
    spawn_error = None
    started = time.monotonic()
    counts = {"stdout": 0, "stderr": 0}
    returncode = None
    with stdout_path.open("wb") as stdout_file, stderr_path.open("wb") as stderr_file:
        stdout_path.chmod(0o600)
        stderr_path.chmod(0o600)
        try:
            process = subprocess.Popen(
                argv, cwd=project, env=safe_environment(), stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
                start_new_session=(os.name == "posix"),
            )
        except OSError as exc:
            spawn_error = f"{type(exc).__name__}: {exc}"
        else:
            _ACTIVE_CHILD = process
            selector = selectors.DefaultSelector()
            assert process.stdout is not None and process.stderr is not None
            selector.register(process.stdout, selectors.EVENT_READ, (stdout_file, "stdout"))
            selector.register(process.stderr, selectors.EVENT_READ, (stderr_file, "stderr"))
            deadline = started + timeout
            try:
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        timed_out = True
                        terminate_process_group(process)
                        break
                    for key, _ in selector.select(min(remaining, 0.2)):
                        chunk = os.read(key.fileobj.fileno(), 64 * 1024)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        output_file, stream_name = key.data
                        available = max(0, max_output - sum(counts.values()))
                        output_file.write(chunk[:available])
                        counts[stream_name] += min(len(chunk), available)
                        if len(chunk) > available:
                            output_limited = True
                            terminate_process_group(process)
                            break
                    if output_limited:
                        break
                try:
                    returncode = process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    terminate_process_group(process)
                    returncode = process.wait(timeout=2)
            finally:
                _ACTIVE_CHILD = None
                selector.close()
                process.stdout.close()
                process.stderr.close()
    elapsed = round(time.monotonic() - started, 3)
    return {
        "exit_code": returncode,
        "timed_out": timed_out,
        "output_limited": output_limited,
        "spawn_error": spawn_error,
        "duration_seconds": elapsed,
        "stdout_artifact": {"path": str(stdout_path), "sha256": file_sha256(stdout_path), "bytes": counts["stdout"]},
        "stderr_artifact": {"path": str(stderr_path), "sha256": file_sha256(stderr_path), "bytes": counts["stderr"]},
    }


def action_argv(action: str, args: argparse.Namespace, run_dir: Path) -> list[str]:
    binary = {"forge-build": "forge", "forge-test": "forge", "slither": "slither", "halmos": "halmos"}[action]
    executable = shutil.which(binary)
    if executable is None:
        raise FileNotFoundError(f"{binary} is not installed")
    if action == "forge-build":
        if args.match_test or args.match_contract:
            raise ValueError("test match flags are only valid for forge-test or halmos")
        # Slither's Foundry no-compile mode consumes build-info artifacts.
        return [executable, "build", "--offline", "--build-info"]
    if action == "halmos":
        # Bounded symbolic execution over the project's symbolic property tests
        # (check_*/test_* functions). Offline, no FFI (never pass --ffi), with a
        # fixed solver so results are reproducible; machine results go to a JSON
        # artifact that classify() reads. A counterexample is a candidate lead,
        # never a finding by itself.
        argv = [executable, "--root", str(args.project.resolve()), "--solver", "z3",
                "--json-output", str(run_dir / "halmos.json"), "--statistics"]
        if args.match_contract:
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", args.match_contract) is None:
                raise ValueError("match-contract must be a literal Solidity contract name")
            argv += ["--contract", args.match_contract]
        if args.match_test:
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", args.match_test) is None:
                raise ValueError("match-test must be a literal Solidity test function name")
            # --function selects a prefix, so check_bug also selects check_bug2.
            # Halmos matches full function signatures; anchor the name before '('.
            argv += ["--match-test", "^" + args.match_test + r"\("]
        return argv
    if action == "forge-test":
        argv = [executable, "test", "--offline", "--build-info"]
        if args.match_test:
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", args.match_test) is None:
                raise ValueError("match-test must be a literal Solidity test function name")
            # Foundry matches the displayed signature, including arguments.
            argv += ["--match-test", "^" + args.match_test + r"\("]
        if args.match_contract:
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", args.match_contract) is None:
                raise ValueError("match-contract must be a literal Solidity contract name")
            # The match input may include a source-path prefix.
            argv += ["--match-contract", args.match_contract + "$"]
        return argv
    if args.match_test or args.match_contract:
        raise ValueError("test match flags are only valid for forge-test or halmos")
    # Slither uses existing Foundry artifacts so it cannot launch a fresh
    # compiler/download through the project framework. JSON goes to bounded stdout.
    return [executable, ".", "--compile-force-framework", "foundry", "--foundry-ignore-compile", "--json", "-"]


def classify_halmos(json_path: Path, match_test: str | None = None,
                    match_contract: str | None = None) -> tuple[str, str, int | None]:
    """Classify a halmos run from its JSON output.

    A per-test counterexample (nonzero exit *with* a concrete model) is a
    candidate lead. A nonzero exit *without* a model means the solver could not
    decide the property (timeout/unavailable), which is incomplete coverage, not
    a finding and not a clean proof. All selected properties proving within
    bounds is a bounded ``pass``.
    """
    try:
        payload = json.loads(json_path.read_text(encoding="utf-8"))
        results = payload.get("test_results")
        if not isinstance(results, dict):
            raise ValueError("missing test_results")
    except (OSError, UnicodeError, ValueError, AttributeError):
        return "incomplete", "halmos produced no parseable JSON result", None
    tests = [t for group in results.values() if isinstance(group, list)
             for t in group if isinstance(t, dict)]
    if not tests:
        return "incomplete", "halmos selected no symbolic property tests", None
    if match_contract and any(not key.endswith(":" + match_contract) for key in results):
        return "incomplete", "halmos result included an unexpected contract", None
    if match_test and any(not isinstance(t.get("name"), str)
                          or not t["name"].startswith(match_test + "(") for t in tests):
        return "incomplete", "halmos result did not match the requested property", None
    counterexamples = 0
    undecided = 0
    for test in tests:
        if test.get("exitcode") == 0:
            continue
        has_model = bool(test.get("models")) or (isinstance(test.get("num_models"), int) and test["num_models"] > 0)
        if has_model:
            counterexamples += 1
        else:
            undecided += 1
    if counterexamples:
        return "findings", "halmos found counterexamples to symbolic properties; manual reproduction required", counterexamples
    if undecided:
        return "incomplete", "halmos could not decide some properties (solver timeout/unavailable); not a clean result", None
    if payload.get("exitcode") != 0:
        return "incomplete", "halmos reported a nonzero overall exit code", None
    return "pass", "halmos proved all selected properties within its bounds", 0


def classify(action: str, execution: dict, stdout_path: Path, args: argparse.Namespace) -> tuple[str, str, int | None]:
    if execution["spawn_error"]:
        return "incomplete", "tool could not start", None
    if execution["timed_out"]:
        return "incomplete", "tool timed out", None
    if execution["output_limited"]:
        return "incomplete", "output byte limit exceeded", None
    if action == "halmos":
        status, reason, count = classify_halmos(stdout_path.parent / "halmos.json",
                                               args.match_test, args.match_contract)
        if status == "pass" and execution["exit_code"] != 0:
            return "incomplete", "halmos exited nonzero despite passing test results", None
        return status, reason, count
    if action != "slither":
        if execution["exit_code"] != 0:
            return "incomplete", "build or test failed; inspect artifacts", None
        if action == "forge-test":
            output = stdout_path.read_text(encoding="utf-8", errors="replace")
            if "[PASS]" not in output:
                return "incomplete", "forge test did not report a passing test", None
            if args.match_test:
                names = re.findall(r"(?m)^\[PASS\]\s+([A-Za-z_][A-Za-z0-9_]*)\(", output)
                if len(names) != 1 or names[0] != args.match_test:
                    return "incomplete", "forge test selection was not exactly one requested test", None
            if args.match_contract and not re.search(
                r"(?m)^Ran\s+\d+\s+tests?\s+for\s+[^\n]*\b" + re.escape(args.match_contract) + r"\s*$", output
            ):
                return "incomplete", "forge test contract could not be verified from output", None
        return "pass", "command exited successfully", None
    try:
        payload = json.loads(stdout_path.read_text(encoding="utf-8"))
        detectors = payload.get("results", {}).get("detectors", [])
        if payload.get("success") is not True or not isinstance(detectors, list):
            return "incomplete", "Slither did not return successful detector JSON", None
    except (OSError, UnicodeError, ValueError, AttributeError):
        return "incomplete", "Slither JSON output could not be parsed", None
    count = len(detectors)
    if count:
        return "findings", "Slither emitted candidate findings; manual reproduction required", count
    if execution["exit_code"] != 0:
        return "incomplete", "Slither exited nonzero without detector findings", count
    return "pass", "Slither completed without detector findings", count


def test_identifier(args: argparse.Namespace) -> str:
    if args.match_contract and args.match_test:
        return args.match_contract + "::" + args.match_test
    if not args.match_contract and not args.match_test:
        return "forge-test:all"
    return "forge-test:contract=" + (args.match_contract or "*") + ";test=" + (args.match_test or "*")


def reuse_manifest(previous_path: Path, current: dict, destination: Path) -> dict:
    try:
        previous = json.loads(previous_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise ValueError(f"cannot read prior manifest: {exc}") from exc
    if not isinstance(previous, dict):
        raise ValueError("prior manifest is not a JSON object")
    old_comparable = {key: value for key, value in previous.items() if key != "created_at_utc"}
    new_comparable = {key: value for key, value in current.items() if key != "created_at_utc"}
    if old_comparable != new_comparable:
        raise ValueError("prior manifest differs from current source, tool, config, or target context")
    shutil.copyfile(previous_path, destination)
    destination.chmod(0o600)
    return previous


def copy_primary_replay(previous_manifest: Path, run_dir: Path, command: str, test_id: str, manifest_hash: str) -> list[str]:
    """Carry primary replay evidence into the independent run's artifact root."""
    primary_dir = previous_manifest.parent
    try:
        prior_result = json.loads((primary_dir / "result.json").read_text(encoding="utf-8"))
        receipt_bytes = (primary_dir / "replay_receipt.json").read_bytes()
        receipt = json.loads(receipt_bytes)
    except (OSError, UnicodeError, ValueError) as exc:
        raise ValueError(f"prior primary replay is missing or malformed: {exc}") from exc
    if not isinstance(prior_result, dict) or not isinstance(receipt, dict):
        raise ValueError("prior primary replay is not a JSON object")
    if (prior_result.get("action"), prior_result.get("status"), prior_result.get("exit_code")) != ("forge-test", "pass", 0):
        raise ValueError("prior run is not a passing forge-test")
    if prior_result.get("manifest_sha256") != manifest_hash or prior_result.get("command") != command or prior_result.get("test_id") != test_id:
        raise ValueError("prior run command, test, or manifest differs")
    expected_receipt = {
        "kind": "replay", "command": command, "test_id": test_id,
        "manifest_sha256": manifest_hash, "exit_code": 0, "result": "pass",
    }
    if any(receipt.get(key) != value for key, value in expected_receipt.items()):
        raise ValueError("prior replay receipt does not match the requested test")
    ref = receipt.get("log_ref")
    match = re.fullmatch(r"stdout\.log#sha256=([0-9a-f]{64})", ref or "")
    if match is None or file_sha256(primary_dir / "stdout.log") != match.group(1):
        raise ValueError("prior replay log hash does not match its receipt")
    receipt_hash = sha256_bytes(receipt_bytes)
    if "replay_receipt.json#sha256=" + receipt_hash not in prior_result.get("evidence_artifact_refs", []):
        raise ValueError("prior result does not bind its replay receipt")
    refs = []
    for source_name, destination_name in (
        ("stdout.log", "stdout.log"),
        ("stderr.log", "stderr.log"),
        ("replay_receipt.json", "primary_replay_receipt.json"),
    ):
        source = primary_dir / source_name
        destination = run_dir / destination_name
        shutil.copyfile(source, destination)
        destination.chmod(0o600)
        refs.append(destination_name + "#sha256=" + file_sha256(destination))
    return refs


def common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--project", type=Path, required=True, help="Foundry project directory")
    parser.add_argument("--output-dir", type=Path, required=True, help="directory for manifests and run artifacts")
    parser.add_argument("--chain-id", type=int, help="optional target chain context, not an RPC request")
    parser.add_argument("--block-number", type=int, help="optional pinned target block context")
    parser.add_argument("--address", help="optional target EVM contract address context")


def main() -> int:
    install_termination_handlers()
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    manifest_parser = sub.add_parser("manifest", help="record exact local source and tool context")
    common_arguments(manifest_parser)
    run_parser = sub.add_parser("run", help="run one allowlisted local analysis action")
    common_arguments(run_parser)
    run_parser.add_argument("action", choices=("forge-build", "forge-test", "slither", "halmos"))
    run_parser.add_argument("--match-test", help="Foundry test name filter")
    run_parser.add_argument("--match-contract", help="Foundry contract name filter")
    run_parser.add_argument("--reuse-manifest", type=Path, help="previous manifest for a second exact-state run")
    run_parser.add_argument("--independent-verifier", help="claimed independent verifier label; requires --reuse-manifest")
    run_parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_SECONDS)
    run_parser.add_argument("--max-output-bytes", type=int, default=DEFAULT_OUTPUT_BYTES)
    args = parser.parse_args()
    project = args.project.resolve()
    output_dir = args.output_dir.resolve()
    try:
        if args.command == "run" and not (1 <= args.timeout <= MAX_TIMEOUT_SECONDS):
            raise ValueError(f"timeout must be 1..{MAX_TIMEOUT_SECONDS} seconds")
        if args.command == "run" and not (1 <= args.max_output_bytes <= MAX_OUTPUT_BYTES):
            raise ValueError(f"max output must be 1..{MAX_OUTPUT_BYTES} bytes")
        if args.command == "run" and args.independent_verifier:
            if args.action != "forge-test" or args.reuse_manifest is None:
                raise ValueError("independent verifier requires forge-test and --reuse-manifest")
            if len(args.independent_verifier) > 80 or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 _.-]*", args.independent_verifier) is None:
                raise ValueError("independent verifier label must be 1..80 plain characters")
        if args.command == "manifest":
            manifest = build_manifest(project, output_dir, output_dir / "source_snapshot.tar", args)
            path = output_dir / "manifest.json"
            write_json(path, manifest)
            print(json.dumps({"manifest": str(path), "environment_manifest_sha256": file_sha256(path)}))
            return 0
        run_dir = output_dir / ("run-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8])
        run_dir.mkdir(parents=True, exist_ok=False, mode=0o700)
        current_manifest = build_manifest(project, output_dir, run_dir / "source_snapshot.tar", args)
        manifest_path = run_dir / "manifest.json"
        previous_manifest = args.reuse_manifest.resolve() if args.reuse_manifest else None
        if previous_manifest:
            manifest = reuse_manifest(previous_manifest, current_manifest, manifest_path)
        else:
            manifest = current_manifest
            write_json(manifest_path, manifest)
        manifest_sha256 = file_sha256(manifest_path)
        primary_refs: list[str] = []
        try:
            argv = action_argv(args.action, args, run_dir)
            if args.action == "forge-test" and manifest["execution_policy"]["forge_test_effective_ffi"] is not False:
                raise ValueError("forge test refused: effective FFI setting is enabled or unknown")
            if args.independent_verifier:
                assert previous_manifest is not None
                primary_refs = copy_primary_replay(previous_manifest, run_dir, shlex.join(argv), test_identifier(args), manifest_sha256)
        except (FileNotFoundError, ValueError) as exc:
            argv = []
            execution = {
                "exit_code": None, "timed_out": False, "output_limited": False,
                "spawn_error": str(exc), "duration_seconds": 0.0,
            }
            for stream in ("stdout", "stderr"):
                path = run_dir / (("independent_" if args.independent_verifier else "") + stream + ".log")
                path.write_bytes(b"")
                path.chmod(0o600)
                execution[stream + "_artifact"] = {"path": str(path), "sha256": file_sha256(path), "bytes": 0}
        else:
            execution = bounded_execute(argv, project, run_dir, args.timeout, args.max_output_bytes,
                                        "independent_" if args.independent_verifier else "")
        current_stdout_name = "independent_stdout.log" if args.independent_verifier else "stdout.log"
        current_stderr_name = "independent_stderr.log" if args.independent_verifier else "stderr.log"
        status, reason, candidate_count = classify(args.action, execution, run_dir / current_stdout_name, args)
        source_drift = False
        source_tree_after_sha256 = None
        try:
            after, _ = source_tree_identity(project, output_dir, args.action)
            source_tree_after_sha256 = after["source_tree_sha256"]
            source_drift = source_tree_after_sha256 != manifest["source_tree_sha256"]
        except (OSError, ValueError, tomllib.TOMLDecodeError):
            source_drift = True
        if source_drift:
            status, reason = "incomplete", "source or dependency inputs changed during analysis"
        try:
            actual_compilers = build_info_compilers(project, manifest["foundry_config"])
        except (OSError, ValueError):
            actual_compilers = []
            status, reason = "incomplete", "Foundry build-info could not be verified"
        actual_compiler_label = compiler_label(actual_compilers)
        if actual_compiler_label:
            if previous_manifest and manifest["environment"]["compiler"] != actual_compiler_label:
                status, reason = "incomplete", "effective compiler changed from reused manifest"
            elif not previous_manifest and manifest["environment"]["compiler"] != actual_compiler_label:
                manifest["environment"]["compiler"] = actual_compiler_label
                manifest["compiler_provenance"]["build_info_versions"] = actual_compilers
                write_json(manifest_path, manifest)
                manifest_sha256 = file_sha256(manifest_path)
        command = shlex.join(argv) if argv else ""
        replay_receipt_path = None
        if args.action == "forge-test" and status == "pass":
            log = execution["stdout_artifact"]
            # Relative to run_dir, the evidence validator's artifact root.
            relative_log = current_stdout_name
            receipt = {
                "receipt_version": 1,
                "kind": "independent_replay" if args.independent_verifier else "replay",
                "command": command,
                "test_id": test_identifier(args),
                "manifest_sha256": manifest_sha256,
                "exit_code": 0,
                "result": "pass",
                "log_ref": relative_log + "#sha256=" + log["sha256"],
            }
            if args.independent_verifier:
                receipt["method"] = "independent_replay"
                receipt["verifier"] = args.independent_verifier
            replay_receipt_path = run_dir / ("independent_replay_receipt.json" if args.independent_verifier else "replay_receipt.json")
            write_json(replay_receipt_path, receipt)
        shared_refs = [
            "source_snapshot.tar#sha256=" + manifest["source_snapshot"]["sha256"],
            "manifest.json#sha256=" + file_sha256(manifest_path),
        ]
        current_refs = [
            current_stdout_name + "#sha256=" + execution["stdout_artifact"]["sha256"],
            current_stderr_name + "#sha256=" + execution["stderr_artifact"]["sha256"],
        ]
        if replay_receipt_path:
            current_refs.append(replay_receipt_path.name + "#sha256=" + file_sha256(replay_receipt_path))
        if args.action == "halmos":
            halmos_json = run_dir / "halmos.json"
            if halmos_json.is_file():
                current_refs.append("halmos.json#sha256=" + file_sha256(halmos_json))
        evidence_refs = shared_refs + primary_refs if args.independent_verifier else shared_refs + current_refs
        result = {
            "schema_version": 1,
            "action": args.action,
            "argv": argv,
            "command": command,
            "test_id": test_identifier(args) if args.action == "forge-test" else None,
            "tool_version": manifest["environment"]["tool_versions"].get({"slither": "slither", "halmos": "halmos"}.get(args.action, "forge")),
            "manifest": str(manifest_path),
            "manifest_sha256": manifest_sha256,
            "status": status,
            "status_reason": reason,
            "candidate_count": candidate_count,
            "source_drift": source_drift,
            "source_tree_after_sha256": source_tree_after_sha256,
            "effective_compiler_versions": actual_compilers,
            "replay_receipt": str(replay_receipt_path) if replay_receipt_path else None,
            "receipt_kind": "independent_replay" if args.independent_verifier else "replay" if replay_receipt_path else None,
            "primary_artifact_refs": shared_refs + primary_refs if args.independent_verifier else shared_refs + current_refs,
            "independent_artifact_refs": current_refs if args.independent_verifier else [],
            "evidence_artifact_refs": evidence_refs,
            **execution,
        }
        result_path = run_dir / "result.json"
        write_json(result_path, result)
        print(json.dumps({"status": status, "result": str(result_path), "result_sha256": file_sha256(result_path)}))
        return 0 if status in {"pass", "findings"} else 2
    except (OSError, ValueError, tomllib.TOMLDecodeError) as exc:
        print(f"analysis manifest failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
