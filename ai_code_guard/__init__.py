"""
AI Code Guard Pro - Industry-grade security scanner for AI-generated code.

Features:
- AST-based analysis with taint tracking
- Entropy-based secret detection
- Prompt injection detection for LLM applications
- Supply chain attack detection
- SARIF output for CI/CD integration
"""

__version__ = "1.0.0"

from .models import Category, Config, Finding, Location, ScanResult, Severity
from .scanner import Scanner, scan

__all__ = [
    "Category",
    "Config",
    "Finding",
    "Location",
    "ScanResult",
    "Scanner",
    "Severity",
    "scan",
]
