"""
Dependency confusion and supply chain security analyzer.

Detects typosquatting packages, suspicious dependencies, and
other supply chain attack vectors.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from ..models import Category, Config, Finding, Location, Severity


@dataclass
class SuspiciousDependency:
    """A known suspicious or typosquatted package."""
    
    name: str
    legitimate_name: str | None
    reason: str
    severity: Severity


# Known typosquatting and malicious packages
SUSPICIOUS_PACKAGES: list[SuspiciousDependency] = [
    # Python typosquats
    SuspiciousDependency("reqeusts", "requests", "Typosquat of requests", Severity.CRITICAL),
    SuspiciousDependency("requets", "requests", "Typosquat of requests", Severity.CRITICAL),
    SuspiciousDependency("djago", "django", "Typosquat of django", Severity.CRITICAL),
    SuspiciousDependency("flaask", "flask", "Typosquat of flask", Severity.CRITICAL),
    SuspiciousDependency("numpyy", "numpy", "Typosquat of numpy", Severity.CRITICAL),
    SuspiciousDependency("panadas", "pandas", "Typosquat of pandas", Severity.CRITICAL),
    SuspiciousDependency("colourama", "colorama", "Typosquat of colorama", Severity.HIGH),
    # npm typosquats
    SuspiciousDependency("crossenv", "cross-env", "Known malicious package", Severity.CRITICAL),
    SuspiciousDependency("lodahs", "lodash", "Typosquat of lodash", Severity.CRITICAL),
    # Suspicious patterns
    SuspiciousDependency("pip", None, "Shadows pip itself", Severity.CRITICAL),
    SuspiciousDependency("os", None, "Shadows stdlib module", Severity.CRITICAL),
    SuspiciousDependency("sys", None, "Shadows stdlib module", Severity.CRITICAL),
]

LEGITIMATE_PACKAGES = {
    "requests", "django", "flask", "numpy", "pandas", "scipy",
    "tensorflow", "pytorch", "torch", "scikit-learn", "matplotlib",
    "pillow", "beautifulsoup4", "selenium", "pytest", "black",
    "fastapi", "uvicorn", "gunicorn", "celery", "redis", "sqlalchemy",
    "pydantic", "httpx", "aiohttp", "boto3", "openai", "anthropic",
}


class DependencyAnalyzer:
    """Analyzer for dependency security issues."""
    
    def __init__(self, filepath: Path, content: str, config: Config):
        self.filepath = filepath
        self.content = content
        self.lines = content.splitlines()
        self.config = config
        self.file_type = self._determine_file_type()
    
    def _determine_file_type(self) -> str | None:
        name = self.filepath.name.lower()
        if name == "requirements.txt":
            return "requirements"
        elif name == "pyproject.toml":
            return "pyproject"
        elif name == "package.json":
            return "npm"
        elif name.endswith(".py"):
            return "python"
        return None
    
    def analyze(self) -> list[Finding]:
        findings: list[Finding] = []
        if self.file_type == "requirements":
            findings.extend(self._analyze_requirements())
        elif self.file_type == "python":
            findings.extend(self._analyze_python_imports())
        return findings
    
    def _analyze_requirements(self) -> Iterator[Finding]:
        for line_num, line in enumerate(self.lines, start=1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            match = re.match(r'^([a-zA-Z0-9_-]+)', line)
            if not match:
                continue
            
            pkg_name = match.group(1)
            
            for suspicious in SUSPICIOUS_PACKAGES:
                if pkg_name.lower() == suspicious.name.lower():
                    yield Finding(
                        rule_id="DEP001",
                        title=f"Suspicious Dependency: {pkg_name}",
                        description=f"{suspicious.reason}",
                        severity=suspicious.severity,
                        category=Category.DEPENDENCY,
                        location=Location(filepath=self.filepath, line=line_num),
                        code_snippet=line,
                        cwe_id="CWE-829",
                    )
            
            yield from self._check_typosquatting(pkg_name, line_num, line)
    
    def _check_typosquatting(self, pkg: str, line_num: int, line: str) -> Iterator[Finding]:
        for legit in LEGITIMATE_PACKAGES:
            dist = self._levenshtein_distance(pkg.lower(), legit.lower())
            if 0 < dist <= 2:
                yield Finding(
                    rule_id="DEP002",
                    title=f"Potential Typosquat: {pkg}",
                    description=f"Package '{pkg}' is similar to '{legit}'",
                    severity=Severity.HIGH if dist == 1 else Severity.MEDIUM,
                    category=Category.DEPENDENCY,
                    location=Location(filepath=self.filepath, line=line_num),
                    code_snippet=line,
                    cwe_id="CWE-829",
                )
    
    def _analyze_python_imports(self) -> Iterator[Finding]:
        import_pattern = re.compile(r'^(?:from|import)\s+([a-zA-Z_][a-zA-Z0-9_]*)')
        for line_num, line in enumerate(self.lines, start=1):
            match = import_pattern.match(line.strip())
            if match:
                module = match.group(1)
                for suspicious in SUSPICIOUS_PACKAGES:
                    if module.lower() == suspicious.name.lower():
                        yield Finding(
                            rule_id="DEP003",
                            title=f"Suspicious Import: {module}",
                            description=suspicious.reason,
                            severity=suspicious.severity,
                            category=Category.DEPENDENCY,
                            location=Location(filepath=self.filepath, line=line_num),
                            code_snippet=line.strip(),
                            cwe_id="CWE-829",
                        )
    
    @staticmethod
    def _levenshtein_distance(s1: str, s2: str) -> int:
        if len(s1) < len(s2):
            return DependencyAnalyzer._levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
        
        prev_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            curr_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = prev_row[j + 1] + 1
                deletions = curr_row[j] + 1
                substitutions = prev_row[j] + (c1 != c2)
                curr_row.append(min(insertions, deletions, substitutions))
            prev_row = curr_row
        
        return prev_row[-1]
