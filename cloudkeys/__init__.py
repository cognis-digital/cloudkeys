"""CLOUDKEYS - defensive leaked-cloud-credential scanner and blast-radius triage.

Standard-library only. Detection/analysis/triage of leaked AWS/GCP/Azure
credentials in source trees and text. This is a DEFENSIVE tool: it finds and
classifies exposed secrets so they can be rotated. It performs no network
calls and no use of any discovered credential.
"""
from .core import (
    Finding,
    ScanResult,
    scan_text,
    scan_path,
    DETECTORS,
    blast_radius,
)

TOOL_NAME = "cloudkeys"
TOOL_VERSION = "1.0.0"

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "Finding",
    "ScanResult",
    "scan_text",
    "scan_path",
    "DETECTORS",
    "blast_radius",
]
