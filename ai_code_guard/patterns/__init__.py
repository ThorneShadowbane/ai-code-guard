"""Security pattern detectors for AI-generated code."""

from typing import List, Type

from .base import BasePattern, Finding, Severity
from .prompt_injection import PROMPT_INJECTION_PATTERNS
from .secrets import SECRETS_PATTERNS
from .injection import INJECTION_PATTERNS
from .data_exfiltration import DATA_EXFILTRATION_PATTERNS


def get_all_patterns() -> List[Type[BasePattern]]:
    """Return all registered pattern classes."""
    return (
        PROMPT_INJECTION_PATTERNS +
        SECRETS_PATTERNS +
        INJECTION_PATTERNS +
        DATA_EXFILTRATION_PATTERNS
    )


def get_patterns_by_category() -> dict:
    """Return patterns organized by category."""
    return {
        "prompt_injection": PROMPT_INJECTION_PATTERNS,
        "secrets": SECRETS_PATTERNS,
        "injection": INJECTION_PATTERNS,
        "data_exfiltration": DATA_EXFILTRATION_PATTERNS,
    }


__all__ = [
    "BasePattern",
    "Finding",
    "Severity",
    "get_all_patterns",
    "get_patterns_by_category",
    "PROMPT_INJECTION_PATTERNS",
    "SECRETS_PATTERNS",
    "INJECTION_PATTERNS",
    "DATA_EXFILTRATION_PATTERNS",
]
