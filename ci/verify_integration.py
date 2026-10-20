#!/usr/bin/env python3
"""Refuse a gate whose index, tracked source or lockfile changed after assembly."""

import argparse
import json
from pathlib import Path
import sys

from assemble_integration import AssemblyError, git


def verify(receipt):
    source = Path(receipt["destination"])
    actual = git(source, "write-tree").stdout.decode().strip()
    if actual != receipt["tree"]:
        raise AssemblyError(f"Tested index drift: expected {receipt['tree']}, got {actual}")
    git(source, "diff", "--exit-code")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    try:
        verify(json.loads(args.receipt.read_text(encoding="utf-8")))
    except (AssemblyError, OSError, ValueError, KeyError) as error:
        print(f"integration verification refused: {error}", file=sys.stderr)
        sys.exit(1)
    print("tested index and tracked sources match the combined-tree receipt")
