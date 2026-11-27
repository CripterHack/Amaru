"""Scan one local file using Amaru's bundled rules and YARA-X."""

import argparse
import json
import os
from pathlib import Path
import sys

import yara_x


SIGNATURES = Path(__file__).resolve().parents[1] / "signatures"


def rule_files(root):
    """Read both catalog directories, surfacing missing and inaccessible paths."""
    def raise_walk_error(error):
        raise error

    files = []
    for name in ("official", "custom"):
        directory = root / name
        paths = []
        for parent, _, filenames in os.walk(directory, onerror=raise_walk_error):
            paths.extend(Path(parent) / file for file in filenames if file.endswith(".yar"))
        if name == "official" and not paths:
            raise ValueError(f"No official .yar rules found in {directory}")
        files.extend(sorted(paths))
    return files


def compile_rules(paths):
    compiler = yara_x.Compiler()
    for path in paths:
        compiler.add_source(path.read_text(encoding="utf-8"), origin=str(path))
    return compiler.build()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path, help="file to scan")
    args = parser.parse_args()
    try:
        if not args.file.is_file():
            raise ValueError(f"Expected a regular file: {args.file}")
        scanner = yara_x.Scanner(compile_rules(rule_files(SIGNATURES)))
        scanner.set_timeout(30)
        result = scanner.scan_file(str(args.file))
    except (OSError, ValueError, yara_x.CompileError, yara_x.ScanError, yara_x.TimeoutError) as error:
        print(error, file=sys.stderr)
        return 2
    matches = sorted(rule.identifier for rule in result.matching_rules)
    print(json.dumps(matches))
    return int(bool(matches))


if __name__ == "__main__":
    sys.exit(main())
