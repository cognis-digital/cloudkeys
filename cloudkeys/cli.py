"""Command-line interface for CLOUDKEYS.

Subcommand:
  scan PATH [PATH ...]   Scan files/dirs (or - for stdin) for leaked cloud keys.

Global flags:
  --version              Print tool version and exit.
  --format {table,json}  Output format (default: table).

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

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Find leaked AWS/GCP/Azure credentials and classify blast radius (defensive).",
    )
    p.add_argument("--version", action="version", version="%s %s" % (TOOL_NAME, TOOL_VERSION))
    p.add_argument("--format", choices=("table", "json"), default="table", help="output format")
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


# Maximum stdin bytes accepted; larger input is rejected with a clear error.
_STDIN_MAX_BYTES = 10 * 1024 * 1024  # 10 MB


def _die(msg: str) -> int:
    """Print *msg* to stderr and return exit code 2."""
    print("cloudkeys error: %s" % msg, file=sys.stderr)
    return 2


def main(argv=None) -> int:
    try:
        return _main(argv)
    except SystemExit:
        # argparse raises SystemExit on --help/--version and parse errors;
        # let those propagate normally.
        raise
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001
        return _die("unexpected error: %s" % exc)


def _main(argv=None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        combined = ScanResult()
        for path in args.paths:
            if path == "-":
                try:
                    raw = sys.stdin.buffer.read(_STDIN_MAX_BYTES + 1)
                except (OSError, AttributeError):
                    # Fallback when stdin has no .buffer (e.g. StringIO in tests).
                    raw_str = sys.stdin.read()
                    raw = raw_str.encode("utf-8", errors="replace")
                if len(raw) > _STDIN_MAX_BYTES:
                    return _die(
                        "stdin exceeds %d-byte limit; pipe a smaller input" % _STDIN_MAX_BYTES
                    )
                text = raw.decode("utf-8", errors="replace")
                combined.files_scanned += 1
                combined.findings.extend(scan_text(text, source="<stdin>"))
            else:
                _merge(combined, scan_path(path))

        if args.format == "json":
            print(json.dumps(combined.to_dict(), indent=2))
        else:
            print(_render_table(combined))

        if combined.errors and combined.files_scanned == 0:
            return 2
        return 1 if combined.count else 0

    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    sys.exit(main())
