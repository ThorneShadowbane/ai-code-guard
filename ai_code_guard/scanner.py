"""Core scanner implementation for AI Code Guard."""

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Set

import yaml

from .patterns import Finding, Severity, get_all_patterns


@dataclass
class ScanConfig:
    """Configuration for the scanner."""
    
    min_severity: Severity = Severity.LOW
    ignore_patterns: List[str] = field(default_factory=lambda: [
        "__pycache__/*",
        "*.pyc",
        ".git/*",
        ".venv/*",
        "venv/*",
        "node_modules/*",
        "*.min.js",
        "*.bundle.js",
        ".env.example",
    ])
    disabled_rules: Set[str] = field(default_factory=set)
    max_file_size: int = 1_000_000  # 1MB
    
    @classmethod
    def from_file(cls, path: Path) -> "ScanConfig":
        """Load configuration from YAML file."""
        if not path.exists():
            return cls()
        
        with open(path) as f:
            data = yaml.safe_load(f) or {}
        
        config = cls()
        
        if "min_severity" in data:
            config.min_severity = Severity(data["min_severity"])
        
        if "ignore" in data:
            config.ignore_patterns.extend(data["ignore"])
        
        if "disable_rules" in data:
            config.disabled_rules = set(data["disable_rules"])
        
        return config


@dataclass
class ScanResult:
    """Results from scanning files."""
    
    findings: List[Finding] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0
    errors: List[str] = field(default_factory=list)
    
    @property
    def total_issues(self) -> int:
        return len(self.findings)
    
    def count_by_severity(self) -> dict:
        """Count findings by severity level."""
        counts = {s: 0 for s in Severity}
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts
    
    @property
    def has_critical(self) -> bool:
        return any(f.severity == Severity.CRITICAL for f in self.findings)
    
    @property
    def has_high(self) -> bool:
        return any(f.severity == Severity.HIGH for f in self.findings)


class Scanner:
    """Main scanner class that coordinates pattern detection."""
    
    # Supported file extensions
    SUPPORTED_EXTENSIONS = {
        ".py", ".js", ".ts", ".jsx", ".tsx", 
        ".java", ".go", ".rb", ".php",
        ".html", ".vue", ".svelte",
    }
    
    def __init__(self, config: Optional[ScanConfig] = None):
        """Initialize scanner with configuration."""
        self.config = config or ScanConfig()
        self.patterns = [
            p() for p in get_all_patterns()
            if p.rule_id not in self.config.disabled_rules
        ]
    
    def scan_file(self, filepath: Path) -> List[Finding]:
        """Scan a single file for security issues."""
        findings = []
        
        # Check file size
        if filepath.stat().st_size > self.config.max_file_size:
            return findings
        
        # Read file content
        try:
            content = filepath.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return findings
        
        # Run all applicable patterns
        for pattern in self.patterns:
            if pattern.should_scan_file(str(filepath)):
                try:
                    pattern_findings = pattern.scan(content, str(filepath))
                    # Filter by severity
                    for f in pattern_findings:
                        if f.severity.priority >= self.config.min_severity.priority:
                            findings.append(f)
                except Exception as e:
                    # Log but don't fail on pattern errors
                    pass
        
        return findings
    
    def scan_directory(self, directory: Path, recursive: bool = True) -> ScanResult:
        """Scan a directory for security issues."""
        result = ScanResult()
        
        # Get all files
        if recursive:
            files = directory.rglob("*")
        else:
            files = directory.glob("*")
        
        for filepath in files:
            # Skip directories
            if filepath.is_dir():
                continue
            
            # Skip unsupported extensions
            if filepath.suffix.lower() not in self.SUPPORTED_EXTENSIONS:
                result.files_skipped += 1
                continue
            
            # Skip ignored patterns
            rel_path = str(filepath.relative_to(directory))
            if self._should_ignore(rel_path):
                result.files_skipped += 1
                continue
            
            # Scan file
            try:
                findings = self.scan_file(filepath)
                result.findings.extend(findings)
                result.files_scanned += 1
            except Exception as e:
                result.errors.append(f"{filepath}: {str(e)}")
        
        # Sort findings by severity (critical first)
        result.findings.sort(key=lambda f: -f.severity.priority)
        
        return result
    
    def scan_path(self, path: Path) -> ScanResult:
        """Scan a file or directory."""
        if path.is_file():
            result = ScanResult()
            result.findings = self.scan_file(path)
            result.files_scanned = 1
            return result
        elif path.is_dir():
            return self.scan_directory(path)
        else:
            result = ScanResult()
            result.errors.append(f"Path not found: {path}")
            return result
    
    def _should_ignore(self, filepath: str) -> bool:
        """Check if file should be ignored based on patterns."""
        for pattern in self.config.ignore_patterns:
            if fnmatch.fnmatch(filepath, pattern):
                return True
            # Also check against just the filename
            if fnmatch.fnmatch(Path(filepath).name, pattern):
                return True
        return False
