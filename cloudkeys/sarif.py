"""SARIF 2.1.0 export for CLOUDKEYS findings.

Emits a Static Analysis Results Interchange Format log (OASIS SARIF v2.1.0)
so cloudkeys findings can be uploaded to GitHub code-scanning, Azure DevOps,
or any SARIF-aware viewer. No network access; pure serialization of the
in-memory ScanResult.

Reference: SARIF v2.1.0, https://docs.oasis-open.org/sarif/sarif/v2.1.0/
"""
from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from .core import ScanResult, Finding

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemata/sarif-schema-2.1.0.json"
)

# SARIF "level" is one of: error | warning | note | none.
# Map cloudkeys severities onto those, and onto numeric security-severity
# scores (the convention GitHub uses for ranking).
_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}
_SECURITY_SEVERITY = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.0",
    "low": "2.0",
}


def _rules(result: "ScanResult") -> list:
    """One reportingDescriptor (rule) per distinct detector seen."""
    seen: dict = {}
    for f in result.findings:
        if f.detector in seen:
            continue
        impact = f.blast_radius
        fix = f.remediation
        seen[f.detector] = {
            "id": f.detector,
            "name": f.detector,
            "shortDescription": {"text": "Leaked %s credential (%s)" % (f.provider, f.detector)},
            "fullDescription": {"text": impact},
            "help": {"text": "Blast radius: %s\nRemediation: %s" % (impact, fix)},
            "defaultConfiguration": {"level": _LEVEL.get(f.severity, "warning")},
            "properties": {
                "security-severity": _SECURITY_SEVERITY.get(f.severity, "5.0"),
                "tags": ["security", "secret", f.provider],
            },
        }
    return list(seen.values())


def _result(f: "Finding") -> dict:
    return {
        "ruleId": f.detector,
        "level": _LEVEL.get(f.severity, "warning"),
        "message": {
            "text": "%s %s credential detected (redacted %s, entropy %.2f). %s"
            % (f.severity.upper(), f.provider, f.match, f.entropy, f.remediation)
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": _uri(f.file)},
                    "region": {"startLine": max(1, f.line)},
                }
            }
        ],
        "properties": {
            "provider": f.provider,
            "severity": f.severity,
            "entropy": f.entropy,
            "blastRadius": f.blast_radius,
        },
    }


def _uri(path: str) -> str:
    # SARIF prefers forward-slash, repo-relative URIs.
    return str(path).replace("\\", "/")


def to_sarif(result: "ScanResult", tool_name: str, tool_version: str) -> dict:
    """Build a SARIF 2.1.0 log dict from a ScanResult."""
    return {
        "version": SARIF_VERSION,
        "$schema": SARIF_SCHEMA,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": tool_version,
                        "informationUri": "https://github.com/cognis-digital/cloudkeys",
                        "rules": _rules(result),
                    }
                },
                "results": [_result(f) for f in result.findings],
            }
        ],
    }


def dumps(result: "ScanResult", tool_name: str, tool_version: str, indent: int = 2) -> str:
    return json.dumps(to_sarif(result, tool_name, tool_version), indent=indent)
