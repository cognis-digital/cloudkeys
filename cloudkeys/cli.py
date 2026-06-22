"""Command-line interface for CLOUDKEYS.

Subcommands:
  scan PATH [PATH ...]   Scan files/dirs (or - for stdin) for leaked cloud keys.
  feeds list             List the real cloud IP-range feeds this tool consumes.
  feeds update           Fetch + cache the feeds (online).
  feeds get <id>         Print a cached/fetched feed ([--offline] = cache only).
  feeds attribute <ip>   Attribute an IP to AWS/GCP via the cached ranges.

Global flags:
  --version                     Print tool version and exit.
  --format {table,json,sarif}   Output format (default: table). sarif = SARIF 2.1.0.

scan flags:
  --attribute                   Also extract IPs found while scanning and
                                attribute them to AWS/GCP using the IP-range
                                feeds (adds cloud context to the report).
  --offline                     With --attribute, serve feeds from cache only
                                (edge / air-gap; never touches the network).

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
from .core import ScanResult, scan_path, scan_text, extract_ips
from . import sarif as _sarif

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# Feed ids this repo is restricted to (cloud domain).
FEED_IDS = ("aws-ip-ranges", "gcp-ip-ranges")


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
    sp.add_argument("--attribute", action="store_true",
                    help="attribute IPs in scanned text to AWS/GCP via IP-range feeds")
    sp.add_argument("--offline", action="store_true",
                    help="with --attribute, use cached feeds only (air-gap)")

    fp = sub.add_parser("feeds", help="cloud IP-range data feeds (real, keyless, offline-capable)")
    fsub = fp.add_subparsers(dest="feeds_cmd", required=True)
    fsub.add_parser("list", help="list the feeds this tool consumes")
    fsub.add_parser("update", help="fetch + cache the feeds (online)")
    fg = fsub.add_parser("get", help="print a cached/fetched feed")
    fg.add_argument("feed", choices=FEED_IDS)
    fg.add_argument("--offline", action="store_true", help="serve from cache only")
    fa = fsub.add_parser("attribute", help="attribute an IP to AWS/GCP")
    fa.add_argument("ip")
    fa.add_argument("--offline", action="store_true", help="serve from cache only")
    return p


def _merge(target: ScanResult, src: ScanResult) -> None:
    target.findings.extend(src.findings)
    target.files_scanned += src.files_scanned
    target.errors.extend(src.errors)


def _render_table(result: ScanResult, attributions=None) -> str:
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
    if attributions:
        lines.append("")
        lines.append("Cloud IP attribution (AWS/GCP IP-range feeds):")
        for ip, a in attributions.items():
            if a:
                lines.append("  %-39s -> %s %s %s" % (
                    ip, a["cloud"].upper(), a["service"], a["region"]))
            else:
                lines.append("  %-39s -> (not in AWS/GCP ranges)" % ip)
    if result.errors:
        lines.append("errors: %d" % len(result.errors))
        for e in result.errors:
            lines.append("  ! %s" % e)
    return "\n".join(lines)


def _gather_ips(paths) -> list:
    """Collect distinct IP tokens from scanned files/dirs (stdin handled by caller)."""
    import os
    ips: list = []
    seen = set()

    def add_from(text):
        for ip in extract_ips(text):
            if ip not in seen:
                seen.add(ip)
                ips.append(ip)

    for path in paths:
        if path == "-":
            continue
        if os.path.isfile(path):
            files = [path]
        elif os.path.isdir(path):
            files = []
            for dp, _, fns in os.walk(path):
                files.extend(os.path.join(dp, fn) for fn in fns)
        else:
            files = []
        for fp in files:
            try:
                with open(fp, "rb") as fh:
                    add_from(fh.read().decode("utf-8", "replace"))
            except OSError:
                continue
    return ips


def _do_feeds(args) -> int:
    from . import feeds as _feeds
    if args.feeds_cmd == "list":
        rows = _feeds.list_feeds()
        if args.format == "json":
            print(json.dumps(rows, indent=2))
        else:
            for r in rows:
                age = r["cached_age_hours"]
                fresh = "uncached" if age is None else "%.1fh old" % age
                print("  %-16s [%-9s] %s" % (r["id"], fresh, r["url"]))
        return 0
    if args.feeds_cmd == "update":
        try:
            res = _feeds.update()
        except ConnectionError as e:
            print("error: %s" % e, file=sys.stderr)
            return 2
        for fid, n in res.items():
            print("  updated %s (%d bytes)" % (fid, n))
        return 0
    if args.feeds_cmd == "get":
        from . import datafeeds
        try:
            data = datafeeds.get(args.feed, offline=args.offline,
                                 catalog=_feeds.relevant_catalog())
        except (FileNotFoundError, ConnectionError) as e:
            print("error: %s" % e, file=sys.stderr)
            return 2
        print(json.dumps(data, indent=2)[:4000])
        return 0
    if args.feeds_cmd == "attribute":
        try:
            a = _feeds.attribute_ip(args.ip, offline=args.offline)
        except (FileNotFoundError, ConnectionError) as e:
            print("error: %s" % e, file=sys.stderr)
            return 2
        if args.format == "json":
            print(json.dumps({"ip": args.ip, "attribution": a}, indent=2))
        elif a:
            print("%s -> %s %s %s (%s)" % (
                args.ip, a["cloud"].upper(), a["service"], a["region"], a["cidr"]))
        else:
            print("%s -> not in AWS/GCP published ranges" % args.ip)
        return 0
    return 2


def main(argv=None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "feeds":
        return _do_feeds(args)

    if args.command == "scan":
        combined = ScanResult()
        stdin_text = None
        for path in args.paths:
            if path == "-":
                stdin_text = sys.stdin.read()
                combined.files_scanned += 1
                combined.findings.extend(scan_text(stdin_text, source="<stdin>"))
            else:
                _merge(combined, scan_path(path))

        attributions = None
        if args.attribute:
            from . import feeds as _feeds
            ips = _gather_ips(args.paths)
            if stdin_text:
                for ip in extract_ips(stdin_text):
                    if ip not in ips:
                        ips.append(ip)
            try:
                attributions = _feeds.attribute_ips(ips, offline=args.offline)
            except (FileNotFoundError, ConnectionError) as e:
                combined.errors.append("feed attribution unavailable: %s" % e)
                attributions = {}

        out = combined.to_dict()
        if attributions is not None:
            out["ip_attributions"] = {ip: a for ip, a in attributions.items()}

        if args.format == "json":
            print(json.dumps(out, indent=2))
        elif args.format == "sarif":
            print(_sarif.dumps(combined, TOOL_NAME, TOOL_VERSION))
        else:
            print(_render_table(combined, attributions))

        if combined.errors and combined.files_scanned == 0:
            return 2
        return 1 if combined.count else 0

    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    sys.exit(main())
