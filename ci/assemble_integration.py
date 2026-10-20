#!/usr/bin/env python3
"""Assemble pinned PR trees in a NEW worktree, without commits or hidden overlays.

Requires Python 3.11+ and Git with merge-tree --write-tree --merge-base (2.40+).
No existing checkout/index/branch is changed. Conflicts fail closed unless an exact
three-blob resolution is declared in the manifest. Build output belongs to the
new worktree; the receipt names the actual tree that must be tested.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


class AssemblyError(Exception):
    pass


def git(source, *args, data=None, env=None, check=True):
    result = subprocess.run(
        ["git", "-C", str(source), *args], input=data, capture_output=True, env=env
    )
    if check and result.returncode:
        raise AssemblyError(
            f"git {' '.join(args)} failed ({result.returncode}):\n"
            + result.stderr.decode("utf-8", errors="replace")
            + result.stdout.decode("utf-8", errors="replace")
        )
    return result


def oid(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{40}", value):
        raise AssemblyError(f"Expected a full immutable SHA-1, got {value!r}")
    return value


def resolve_conflicts(source, tree, output, resolutions):
    stages = {}
    for line in output.splitlines()[1:]:
        match = re.fullmatch(r"([0-7]{6}) ([0-9a-f]{40}) ([123])\t(.+)", line)
        if match:
            mode, blob, stage, path = match.groups()
            stages.setdefault(path, {})[stage] = (mode, blob)
    if not stages:
        raise AssemblyError(f"Merge failed without recognized conflict stages:\n{output}")
    with tempfile.TemporaryDirectory(prefix="effectcraft-index-") as tmp:
        env = {**os.environ, "GIT_INDEX_FILE": str(Path(tmp) / "index")}
        git(source, "read-tree", tree, env=env)
        for path, entries in stages.items():
            rule = next((r for r in resolutions if r["path"] == path), None)
            blobs = {key: value[1] for key, value in entries.items()}
            if (
                rule is None
                or rule.get("strategy") != "append-ours-to-theirs"
                or blobs != rule["stages"]
                or {value[0] for value in entries.values()} != {"100644"}
            ):
                raise AssemblyError(f"Unapproved merge conflict in {path}: {blobs}\n{output}")
            base, ours, theirs = (git(source, "cat-file", "blob", blobs[stage]).stdout for stage in ("1", "2", "3"))
            # The approved conflict is two independent groups of appended tests.
            # Git's union can align their closing braces and produce invalid Rust.
            # Preserve the entire incoming file, then the exact pure-append side.
            if not ours.startswith(base) or len(ours) == len(base) or not theirs.endswith(b"\n"):
                raise AssemblyError(f"Expected a pure append on the ours side in {path}")
            merged = theirs + ours[len(base):]
            blob = git(source, "hash-object", "-w", "--stdin", data=merged).stdout.decode().strip()
            if blob != oid(rule["result"]):
                raise AssemblyError(f"Resolution content drift in {path}: got {blob}")
            git(source, "update-index", "--add", "--cacheinfo", f"100644,{blob},{path}", env=env)
        return git(source, "write-tree", env=env).stdout.decode().strip(), sorted(stages)


def assemble(source, manifest, fetch=False, check_live=False, patch_root=None):
    tree = oid(manifest["base"])
    entries = manifest["pull_requests"]
    if len({p["number"] for p in entries}) != len(entries):
        raise AssemblyError("Duplicate PR in manifest")
    remote = manifest["repository"]
    if not re.fullmatch(r"https://github.com/[\w.-]+/[\w.-]+(?:\.git)?", remote):
        raise AssemblyError("Expected an HTTPS GitHub repository URL")
    steps = []
    for entry in entries:
        base, head = oid(entry["base"]), oid(entry["head"])
        if base != manifest["base"]:
            raise AssemblyError("This assembly requires a common explicitly pinned base")
        if not isinstance(entry["number"], int) or entry["number"] <= 0:
            raise AssemblyError("Expected a positive PR number")
        if check_live:
            ref = f"refs/pull/{entry['number']}/head"
            actual = git(source, "ls-remote", remote, ref).stdout.decode().split()
            if not actual or actual[0] != head:
                raise AssemblyError(f"PR #{entry['number']} moved: expected {head}, found {actual}")
        if fetch:
            # Fetch objects only: no shared branch, remote-tracking ref or FETCH_HEAD mutation.
            git(source, "fetch", "--no-tags", "--no-write-fetch-head", remote, head)
        for revision in (base, head):
            git(source, "cat-file", "-e", revision + "^{commit}")
        result = git(source, "merge-tree", "--write-tree", "--merge-base=" + base, tree, head, check=False)
        output = result.stdout.decode("utf-8", errors="replace")
        if result.returncode not in (0, 1):
            raise AssemblyError(f"Merge-tree failed: {result.stderr.decode(errors='replace')}")
        next_tree = oid(output.splitlines()[0])
        resolved = []
        if result.returncode == 1:
            next_tree, resolved = resolve_conflicts(source, next_tree, output, manifest.get("resolutions", []))
        steps.append({"number": entry["number"], "base": base, "head": head, "tree": next_tree, "resolved": resolved})
        tree = next_tree
    patches = []
    patch_root = Path(patch_root or source).resolve()
    for patch in manifest.get("patches", []):
        path = (patch_root / patch["path"]).resolve()
        if not path.is_relative_to(patch_root):
            raise AssemblyError("Declared patch must stay within the manifest directory")
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if digest != patch["sha256"]:
            raise AssemblyError(f"Declared patch digest mismatch: {patch['path']}")
        with tempfile.TemporaryDirectory(prefix="effectcraft-patch-index-") as tmp:
            env = {**os.environ, "GIT_INDEX_FILE": str(Path(tmp) / "index")}
            git(source, "read-tree", tree, env=env)
            git(source, "apply", "--cached", "--check", "--binary", "-", data=data, env=env)
            git(source, "apply", "--cached", "--binary", "-", data=data, env=env)
            tree = git(source, "write-tree", env=env).stdout.decode().strip()
        patches.append({"path": patch["path"], "sha256": digest, "tree": tree})
    if tree != oid(manifest["expected_tree"]):
        raise AssemblyError(f"Assembled tree drift: expected {manifest['expected_tree']}, got {tree}")
    return {"kind": "combined-pinned-pr-trees", "base": manifest["base"], "tree": tree, "steps": steps, "patches": patches}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path.cwd())
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--destination", type=Path, help="Must not exist; omit to verify tree only")
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--fetch", action="store_true")
    parser.add_argument("--check-live", action="store_true", help="Refuse if any PR head has moved")
    args = parser.parse_args()
    source = args.source.resolve()
    destination = args.destination.resolve() if args.destination else None
    try:
        if args.receipt.exists():
            raise AssemblyError("Receipt already exists; choose a new evidence path")
        if destination and (destination.exists() or destination.is_relative_to(source)):
            raise AssemblyError("Destination must be absent and outside the source checkout")
        manifest_bytes = args.manifest.read_bytes()
        manifest = json.loads(manifest_bytes)
        receipt = assemble(source, manifest, args.fetch, args.check_live, args.manifest.parent)
        receipt["manifest_sha256"] = hashlib.sha256(manifest_bytes).hexdigest()
        if destination:
            git(source, "worktree", "add", "--detach", str(destination), manifest["base"])
            # This is the only checkout/index mutation, in the worktree just created above.
            git(destination, "read-tree", "--reset", "-u", receipt["tree"])
            actual = git(destination, "write-tree").stdout.decode().strip()
            if actual != receipt["tree"]:
                raise AssemblyError("Checked-out index does not match the verified assembly")
            git(destination, "diff", "--exit-code")
            receipt["destination"] = str(destination)
        args.receipt.parent.mkdir(parents=True, exist_ok=True)
        args.receipt.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(receipt, indent=2))
        return 0
    except (AssemblyError, OSError, ValueError, KeyError, IndexError) as error:
        print(f"integration assembly refused: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
