"""Core detection engine for CLOUDKEYS.

Real logic: regex-based detectors for common cloud credential formats, a
few structural validators (e.g. AWS access-key-id checksum-ish prefix rules,
base64 shape checks), entropy gating to cut false positives, and a
blast-radius classifier that maps a credential type to its likely
impact/severity and recommended remediation.

No network access. No credential is ever used.
"""
from __future__ import annotations

import math
import os
import re
from dataclasses import dataclass, field, asdict
from typing import Callable, Iterable, Optional

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    detector: str            # detector id, e.g. "aws_access_key_id"
    provider: str            # aws | gcp | azure | generic
    severity: str            # critical | high | medium | low
    file: str                # path or "<text>"
    line: int                # 1-based line number
    match: str               # redacted match
    raw_len: int             # length of the raw secret (un-redacted)
    entropy: float           # shannon entropy of the secret (bits/char)
    blast_radius: str        # human-readable impact summary
    remediation: str         # what to do

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanResult:
    findings: list = field(default_factory=list)
    files_scanned: int = 0
    errors: list = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.findings)

    def to_dict(self) -> dict:
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        counts: dict = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return {
            "files_scanned": self.files_scanned,
            "finding_count": self.count,
            "severity_counts": dict(sorted(counts.items(), key=lambda kv: sev_order.get(kv[0], 9))),
            "errors": self.errors,
            "findings": [f.to_dict() for f in self.findings],
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def shannon_entropy(s: str) -> float:
    """Shannon entropy in bits per character."""
    if not s:
        return 0.0
    freq: dict = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    ent = 0.0
    for c in freq.values():
        p = c / n
        ent -= p * math.log2(p)
    return round(ent, 3)


def redact(secret: str) -> str:
    """Show first 4 and last 2 chars, mask the middle. Never leak full secret."""
    if len(secret) <= 8:
        return secret[0:2] + "*" * max(0, len(secret) - 2)
    return secret[:4] + "*" * (len(secret) - 6) + secret[-2:]


# ---------------------------------------------------------------------------
# Blast-radius classification
# ---------------------------------------------------------------------------

_BLAST = {
    "aws_access_key_id": (
        "AWS account access. Paired with a secret key this grants API access "
        "scoped to the IAM principal's policies (potentially full account).",
        "Deactivate/delete the key in IAM immediately, rotate, audit CloudTrail "
        "for use, and review the principal's attached policies.",
    ),
    "aws_secret_access_key": (
        "AWS secret half of a signing pair. Combined with the access key id it "
        "authenticates signed API calls.",
        "Rotate the associated access key, revoke sessions, audit CloudTrail.",
    ),
    "aws_session_token": (
        "Temporary AWS STS session credential. Time-limited but live until "
        "expiry.",
        "Revoke the issuing role session; tokens cannot be individually revoked, "
        "so revoke the role's active sessions and rotate the source key.",
    ),
    "gcp_service_account_key": (
        "GCP service-account private key (JSON). Impersonates the service "
        "account with all its IAM roles.",
        "Disable/delete the key in IAM & Admin > Service Accounts, rotate, audit "
        "Cloud Audit Logs.",
    ),
    "gcp_api_key": (
        "GCP API key. Scope depends on API restrictions; unrestricted keys can "
        "call billable APIs.",
        "Regenerate the key, add API/application restrictions, audit usage.",
    ),
    "azure_storage_key": (
        "Azure Storage account key. Full data-plane access to all containers/ "
        "blobs/files in the account.",
        "Rotate the storage account key (key1/key2), prefer SAS tokens or "
        "Entra ID, audit storage analytics logs.",
    ),
    "azure_client_secret": (
        "Azure AD app client secret. Authenticates as the app registration / "
        "service principal with its granted permissions.",
        "Remove the secret in App registrations > Certificates & secrets, rotate, "
        "audit sign-in logs.",
    ),
    "azure_sas_token": (
        "Azure Shared Access Signature. Delegated, often broad and long-lived "
        "access to storage resources.",
        "Rotate the signing key to invalidate the SAS, reissue least-privilege "
        "short-lived SAS.",
    ),
    "private_key_pem": (
        "PEM private key. Could sign tokens, decrypt traffic, or authenticate "
        "as a host/user.",
        "Treat the key as compromised: revoke, reissue certificates, rotate.",
    ),
    "generic_high_entropy": (
        "Unclassified high-entropy secret near a credential keyword. Scope "
        "unknown; treat as sensitive.",
        "Identify the system, rotate the value, scope its permissions.",
    ),
}


def blast_radius(detector: str) -> tuple:
    """Return (impact, remediation) for a detector id."""
    return _BLAST.get(detector, _BLAST["generic_high_entropy"])


# ---------------------------------------------------------------------------
# Detectors
# ---------------------------------------------------------------------------


@dataclass
class Detector:
    id: str
    provider: str
    severity: str
    pattern: re.Pattern
    group: int = 0
    min_entropy: float = 0.0
    validate: Optional[Callable[[str], bool]] = None


def _valid_aws_akid(s: str) -> bool:
    # AWS access key ids start with a known principal prefix and are 20 chars.
    return len(s) == 20 and s[:4] in {
        "AKIA", "ASIA", "AROA", "AIDA", "AGPA", "AIPA", "ANPA", "ANVA", "ABIA", "ACCA",
    }


DETECTORS: list = [
    Detector(
        id="aws_access_key_id",
        provider="aws",
        severity="high",
        pattern=re.compile(r"\b((?:AKIA|ASIA|AROA|AIDA|AGPA|AIPA|ANPA|ANVA|ABIA|ACCA)[A-Z0-9]{16})\b"),
        group=1,
        validate=_valid_aws_akid,
    ),
    Detector(
        id="aws_secret_access_key",
        provider="aws",
        severity="critical",
        # Keyword-anchored to avoid matching arbitrary 40-char base64 blobs.
        pattern=re.compile(
            r"(?i)aws[_-]?secret[_-]?access[_-]?key[\"'\s:=]+([A-Za-z0-9/+=]{40})"
        ),
        group=1,
        min_entropy=4.0,
    ),
    Detector(
        id="aws_session_token",
        provider="aws",
        severity="high",
        pattern=re.compile(
            r"(?i)aws[_-]?session[_-]?token[\"'\s:=]+([A-Za-z0-9/+=]{100,})"
        ),
        group=1,
        min_entropy=4.2,
    ),
    Detector(
        id="gcp_service_account_key",
        provider="gcp",
        severity="critical",
        pattern=re.compile(r'"type"\s*:\s*"service_account".*?"private_key_id"\s*:\s*"([a-f0-9]{40})"', re.DOTALL),
        group=1,
    ),
    Detector(
        id="gcp_api_key",
        provider="gcp",
        severity="high",
        pattern=re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
        group=1,
    ),
    Detector(
        id="azure_storage_key",
        provider="azure",
        severity="critical",
        pattern=re.compile(
            r"(?i)AccountKey=([A-Za-z0-9/+]{86}==)"
        ),
        group=1,
        min_entropy=4.5,
    ),
    Detector(
        id="azure_client_secret",
        provider="azure",
        severity="critical",
        # Keyword-anchored Azure AD client secret (mod3.* style and generic).
        pattern=re.compile(
            r"(?i)(?:client[_-]?secret|azure[_-]?client[_-]?secret)[\"'\s:=]+([A-Za-z0-9~._\-]{34,44})"
        ),
        group=1,
        min_entropy=3.8,
    ),
    Detector(
        id="azure_sas_token",
        provider="azure",
        severity="high",
        pattern=re.compile(r"(?i)\b(sv=20\d\d-\d\d-\d\d&[^\s\"']*?sig=[A-Za-z0-9%/+]{20,})"),
        group=1,
    ),
    Detector(
        id="private_key_pem",
        provider="generic",
        severity="critical",
        pattern=re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
        group=0,
    ),
]


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------

_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".mypy_cache"}
_MAX_BYTES = 5 * 1024 * 1024  # skip files larger than 5 MB


def _looks_binary(data: bytes) -> bool:
    return b"\x00" in data[:4096]


def scan_text(text: str, source: str = "<text>") -> list:
    """Scan a string, returning a list of Finding objects."""
    findings: list = []
    # Precompute line start offsets for line-number lookup.
    line_starts = [0]
    for m in re.finditer(r"\n", text):
        line_starts.append(m.end())

    def line_of(pos: int) -> int:
        lo, hi = 0, len(line_starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if line_starts[mid] <= pos:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1

    seen = set()
    for det in DETECTORS:
        for m in det.pattern.finditer(text):
            secret = m.group(det.group)
            if not secret:
                continue
            ent = shannon_entropy(secret)
            if ent < det.min_entropy:
                continue
            if det.validate and not det.validate(secret):
                continue
            pos = m.start(det.group)
            key = (det.id, pos, secret)
            if key in seen:
                continue
            seen.add(key)
            impact, fix = blast_radius(det.id)
            findings.append(
                Finding(
                    detector=det.id,
                    provider=det.provider,
                    severity=det.severity,
                    file=source,
                    line=line_of(pos),
                    match=redact(secret),
                    raw_len=len(secret),
                    entropy=ent,
                    blast_radius=impact,
                    remediation=fix,
                )
            )
    findings.sort(key=lambda f: (f.file, f.line, f.detector))
    return findings


def _iter_files(root: str) -> Iterable[str]:
    if os.path.isfile(root):
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for name in filenames:
            yield os.path.join(dirpath, name)


def scan_path(path: str) -> ScanResult:
    """Scan a file or directory tree. Skips binary/oversized files."""
    result = ScanResult()
    if not os.path.exists(path):
        result.errors.append("path not found: %s" % path)
        return result
    for fp in _iter_files(path):
        try:
            if os.path.getsize(fp) > _MAX_BYTES:
                continue
            with open(fp, "rb") as fh:
                data = fh.read()
            if _looks_binary(data):
                continue
            text = data.decode("utf-8", errors="replace")
        except (OSError, ValueError) as exc:
            result.errors.append("%s: %s" % (fp, exc))
            continue
        result.files_scanned += 1
        result.findings.extend(scan_text(text, source=fp))
    result.findings.sort(key=lambda f: (f.file, f.line, f.detector))
    return result
