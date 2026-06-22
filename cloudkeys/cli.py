"""Command-line interface for CLOUDKEYS.

Subcommand:
  scan PATH [PATH ...]   Scan files/dirs (or - for stdin) for leaked cloud keys.

Global flags:
  --version                     Print tool version and exit.
  --format {table,json,sarif}   Output format (default: table). sarif = SARIF 2.1.0.

Exit codes:
  0  no findings
  1  one or more findings
  2  usage / runtime error
"""
from __future__ import annotations

import argparse
import json
import sys

from . import TOOL_NAME, TOOL_VERSION
from .core import ScanResult, scan_path, scan_text
from . import sarif as _sarif

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Find leaked AWS/GCP/Azure credentials and classify blast radius (defensive).",
    )
    p.add_argument("--version", action="version", version="%s %s" % (TOOL_NAME, TOOL_VERSION))
    p.add_argument(
        "--format",
        choices=("table", "json", "sarif"),
        default="table",
        help="output format (table | json | sarif 2.1.0)",
    )
    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("scan", help="scan files/dirs (or - for stdin) for leaked keys")
    sp.add_argument("paths", nargs="+", help="files/directories to scan, or - for stdin")
    return p


def _merge(target: ScanResult, src: ScanResult) -> None:
    target.findings.extend(src.findings)
    target.files_scanned += src.files_scanned
    target.errors.extend(src.errors)


def _render_table(result: ScanResult) -> str:
    lines = []
    result.findings.sort(key=lambda f: (_SEV_ORDER.get(f.severity, 9), f.file, f.line))
    if not result.findings:
        lines.append("No leaked credentials found. (files scanned: %d)" % result.files_scanned)
    else:
        lines.append("%-9s %-26s %-7s %s" % ("SEVERITY", "DETECTOR", "PROV", "LOCATION"))
        lines.append("-" * 78)
        for f in result.findings:
            loc = "%s:%d" % (f.file, f.line)
            lines.append("%-9s %-26s %-7s %s" % (f.severity.upper(), f.detector, f.provider, loc))
            lines.append("    match: %s  (entropy %.2f)" % (f.match, f.entropy))
            lines.append("    blast: %s" % f.blast_radius)
            lines.append("    fix:   %s" % f.remediation)
        lines.append("-" * 78)
        counts = result.to_dict()["severity_counts"]
        summary = ", ".join("%s=%d" % (k, v) for k, v in counts.items())
        lines.append("%d finding(s) across %d file(s): %s" % (result.count, result.files_scanned, summary))
    if result.errors:
        lines.append("errors: %d" % len(result.errors))
        for e in result.errors:
            lines.append("  ! %s" % e)
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        combined = ScanResult()
        for path in args.paths:
            if path == "-":
                text = sys.stdin.read()
                combined.files_scanned += 1
                combined.findings.extend(scan_text(text, source="<stdin>"))
            else:
                _merge(combined, scan_path(path))

        if args.format == "json":
            print(json.dumps(combined.to_dict(), indent=2))
        elif args.format == "sarif":
            print(_sarif.dumps(combined, TOOL_NAME, TOOL_VERSION))
        else:
            print(_render_table(combined))

        if combined.errors and combined.files_scanned == 0:
            return 2
        return 1 if combined.count else 0

    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    sys.exit(main())
