#!/usr/bin/env python3
"""Check untracked publish candidates, the Git index and locally reachable history by filename."""

import argparse
import os
from pathlib import Path
import subprocess
import sys


def restricted(path):
    parts = path.lower().split("/")
    name = parts[-1]
    if parts[0] in {
        ".agents", ".claude", ".codex", "data", "review", "transcripts", "dist",
        "artex_defi_detection_pack", "artex_defi_detection_pack.zip", "security_prompt.txt",
        "config.json", "artex", "artex.old", "artex.failed", "artex.upgrade.json",
    } or parts[0].startswith("artex.new"):
        return True
    if ".ssh" in parts or ".aws" in parts:
        return True
    if (name == ".env" or name.startswith(".env.")) and path != ".env.example":
        return True
    if name in {"openrouter_key", "id_rsa", "id_ed25519"} or name.startswith("openrouter_key."):
        return True
    if name.endswith((".key", ".pem", ".p12", ".pfx", ".db", ".db-wal", ".db-shm")):
        return True
    if parts[:3] == ["server", "webui", "dist"]:
        return True
    return len(parts) >= 2 and parts[0] == "web" and parts[1] in {
        "node_modules", ".next", "out", "tsconfig.tsbuildinfo", "next-env.d.ts",
    }


def collect_matches(git, arguments):
    matches = set()
    entries_checked = 0
    # A NUL delimiter preserves even tabs and newlines in filenames. Stream the
    # history since names can occur in many commits across many branches.
    with subprocess.Popen(git + arguments, stdout=subprocess.PIPE) as process:
        pending = b""
        while block := process.stdout.read(65536):
            entries = (pending + block).split(b"\0")
            pending = entries.pop()
            for entry in entries:
                if entry:
                    entries_checked += 1
                    path = os.fsdecode(entry)
                    if restricted(path):
                        matches.add(path)
        if process.wait():
            raise RuntimeError("Git could not enumerate every path.")
        if pending:
            raise RuntimeError("Git returned an incomplete path list.")
    return entries_checked, matches


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd(), help="working tree to check")
    args = parser.parse_args()
    try:
        root = subprocess.check_output(
            ["git", "-C", args.repo, "rev-parse", "--show-toplevel"], stderr=subprocess.DEVNULL
        ).removesuffix(b"\n")
    except (OSError, subprocess.CalledProcessError):
        print("Git metadata unavailable. Cannot check publish candidates, the index or history.", file=sys.stderr)
        return 2
    git = ["git", "--no-replace-objects", "-C", os.fsdecode(root)]
    try:
        shallow = subprocess.check_output(git + ["rev-parse", "--is-shallow-repository"]).strip()
        if shallow not in (b"true", b"false"):
            raise RuntimeError("Cannot determine whether the checkout is shallow.")
        candidate_count, candidates = collect_matches(git, ["ls-files", "--others", "--exclude-standard", "-z"])
        index_count, index = collect_matches(git, ["ls-files", "--cached", "-z"])
        commit_count = int(subprocess.check_output(git + ["rev-list", "--all", "--count"]))
        history_count, history = collect_matches(git, [
            "log", "--all", "--root", "-m", "--no-renames", "--no-ext-diff", "--no-textconv",
            "--no-notes", "--no-show-signature", "--format=", "--name-only", "-z", "--",
        ])
    except (OSError, RuntimeError, ValueError, subprocess.CalledProcessError) as error:
        print(f"Git path check incomplete. {error}", file=sys.stderr)
        return 2

    groups = (("untracked", candidates), ("index", index), ("history", history))
    for path in sorted(candidates | index | history):
        locations = ", ".join(label for label, paths in groups if path in paths)
        print(f"{locations}: {ascii(path)}")
    print(f"Untracked, non-ignored files: {candidate_count} checked, {len(candidates)} restricted.")
    print(f"Index entries: {index_count} checked, {len(index)} restricted paths.")
    if commit_count:
        print(f"Locally reachable commits: {commit_count}. Historical path entries: {history_count} checked, "
              f"{len(history)} restricted paths.")
    else:
        print("No local commit history to check.")
    if shallow == b"true":
        print("Shallow checkout. Fetch full history and rerun the check.", file=sys.stderr)
        return 2
    return int(bool(candidates or index or history))


if __name__ == "__main__":
    sys.exit(main())
