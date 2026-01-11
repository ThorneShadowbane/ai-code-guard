"""AI Code Guard - Detect security vulnerabilities in AI-generated code."""

__version__ = "0.1.0"
__author__ = "Anjali Gopinadhan Nair"

from .scanner import Scanner, ScanConfig, ScanResult
from .patterns import Finding, Severity

__all__ = [
    "Scanner",
    "ScanConfig", 
    "ScanResult",
    "Finding",
    "Severity",
]
