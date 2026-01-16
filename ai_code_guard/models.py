"""Core data models and types for AI Code Guard Pro."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any


class Severity(Enum):
    """Severity levels following CVSS conventions."""
    
    CRITICAL = auto()  # Immediate exploitation risk, RCE, data breach
    HIGH = auto()       # Serious vulnerability, requires attention
    MEDIUM = auto()     # Moderate risk, should be addressed
    LOW = auto()        # Minor issue, informational
    INFO = auto()       # Best practice recommendation
    
    def __str__(self) -> str:
        return self.name
    
    def __lt__(self, other: Severity) -> bool:
        return self.value > other.value  # Lower value = higher severity
    
    @property
    def color(self) -> str:
        """Rich color for terminal output."""
        return {
            Severity.CRITICAL: "red bold",
            Severity.HIGH: "red",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "blue",
            Severity.INFO: "dim",
        }[self]
    
    @property
    def emoji(self) -> str:
        return {
            Severity.CRITICAL: "🔴",
            Severity.HIGH: "🟠",
            Severity.MEDIUM: "🟡",
            Severity.LOW: "🔵",
            Severity.INFO: "⚪",
        }[self]


class Category(Enum):
    """Vulnerability categories aligned with CWE/OWASP."""
    
    PROMPT_INJECTION = "Prompt Injection"
    SECRETS = "Hardcoded Secrets"
    INJECTION = "Injection Vulnerabilities"
    PATH_TRAVERSAL = "Path Traversal"
    CRYPTO = "Cryptographic Issues"
    DESERIALIZATION = "Insecure Deserialization"
    SSRF = "Server-Side Request Forgery"
    DATA_EXPOSURE = "Sensitive Data Exposure"
    DEPENDENCY = "Dependency Confusion"
    AUTH = "Authentication Issues"
    MISCONFIGURATION = "Security Misconfiguration"


@dataclass(frozen=True)
class Location:
    """Source code location for a finding."""
    
    filepath: Path
    line: int
    column: int = 0
    end_line: int | None = None
    end_column: int | None = None
    
    def __str__(self) -> str:
        return f"{self.filepath}:{self.line}"
    
    @property
    def sarif_region(self) -> dict[str, Any]:
        """Convert to SARIF region format."""
        region: dict[str, Any] = {
            "startLine": self.line,
            "startColumn": self.column + 1,  # SARIF uses 1-based columns
        }
        if self.end_line:
            region["endLine"] = self.end_line
        if self.end_column:
            region["endColumn"] = self.end_column + 1
        return region


@dataclass
class Finding:
    """A security finding/vulnerability."""
    
    rule_id: str
    title: str
    description: str
    severity: Severity
    category: Category
    location: Location
    code_snippet: str = ""
    cwe_id: str | None = None
    owasp_id: str | None = None
    fix_suggestion: str = ""
    references: list[str] = field(default_factory=list)
    confidence: float = 1.0  # 0.0 to 1.0
    metadata: dict[str, Any] = field(default_factory=dict)
    
    @property
    def fingerprint(self) -> str:
        """Unique identifier for deduplication."""
        content = f"{self.rule_id}:{self.location.filepath}:{self.location.line}:{self.code_snippet[:100]}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def to_sarif(self) -> dict[str, Any]:
        """Convert to SARIF result format."""
        result: dict[str, Any] = {
            "ruleId": self.rule_id,
            "level": self._sarif_level,
            "message": {"text": self.description},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": str(self.location.filepath)},
                    "region": self.location.sarif_region,
                }
            }],
            "fingerprints": {"primary": self.fingerprint},
        }
        if self.fix_suggestion:
            result["fixes"] = [{
                "description": {"text": self.fix_suggestion}
            }]
        return result
    
    @property
    def _sarif_level(self) -> str:
        return {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "note",
        }[self.severity]


@dataclass
class RuleDefinition:
    """Definition of a security rule."""
    
    rule_id: str
    name: str
    description: str
    severity: Severity
    category: Category
    cwe_ids: list[str] = field(default_factory=list)
    owasp_ids: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    enabled: bool = True
    
    def to_sarif_rule(self) -> dict[str, Any]:
        """Convert to SARIF rule format."""
        rule: dict[str, Any] = {
            "id": self.rule_id,
            "name": self.name,
            "shortDescription": {"text": self.name},
            "fullDescription": {"text": self.description},
            "defaultConfiguration": {
                "level": {
                    Severity.CRITICAL: "error",
                    Severity.HIGH: "error",
                    Severity.MEDIUM: "warning",
                    Severity.LOW: "note",
                    Severity.INFO: "note",
                }[self.severity]
            },
            "properties": {
                "category": self.category.value,
                "severity": str(self.severity),
            }
        }
        if self.cwe_ids:
            rule["properties"]["cwe"] = self.cwe_ids
        if self.owasp_ids:
            rule["properties"]["owasp"] = self.owasp_ids
        return rule


@dataclass
class ScanResult:
    """Result of a security scan."""
    
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    scan_duration_ms: float = 0.0
    errors: list[str] = field(default_factory=list)
    
    @property
    def by_severity(self) -> dict[Severity, list[Finding]]:
        """Group findings by severity."""
        result: dict[Severity, list[Finding]] = {s: [] for s in Severity}
        for f in self.findings:
            result[f.severity].append(f)
        return result
    
    @property
    def by_category(self) -> dict[Category, list[Finding]]:
        """Group findings by category."""
        result: dict[Category, list[Finding]] = {c: [] for c in Category}
        for f in self.findings:
            result[f.category].append(f)
        return result
    
    def has_blocking_issues(self, threshold: Severity = Severity.HIGH) -> bool:
        """Check if any findings meet or exceed the severity threshold."""
        return any(f.severity.value <= threshold.value for f in self.findings)


@dataclass
class Config:
    """Scanner configuration."""
    
    min_severity: Severity = Severity.LOW
    ignore_patterns: list[str] = field(default_factory=list)
    disabled_rules: set[str] = field(default_factory=set)
    custom_rules_path: Path | None = None
    max_file_size_kb: int = 1024
    follow_symlinks: bool = False
    scan_hidden: bool = False
    parallel_workers: int = 4
    
    # Secret scanning config
    entropy_threshold: float = 4.5
    min_secret_length: int = 16
    
    # AI-specific config
    detect_placeholder_secrets: bool = True
    detect_prompt_injection: bool = True
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Config:
        """Create config from dictionary."""
        config = cls()
        if "min_severity" in data:
            config.min_severity = Severity[data["min_severity"].upper()]
        if "ignore" in data:
            config.ignore_patterns = data["ignore"]
        if "disable_rules" in data:
            config.disabled_rules = set(data["disable_rules"])
        if "max_file_size_kb" in data:
            config.max_file_size_kb = data["max_file_size_kb"]
        if "entropy_threshold" in data:
            config.entropy_threshold = data["entropy_threshold"]
        return config
