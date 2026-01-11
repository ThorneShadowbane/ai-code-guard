"""Base classes for security pattern detection."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List, Optional


class Severity(Enum):
    """Severity levels for security findings."""
    
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    
    @property
    def emoji(self) -> str:
        """Return emoji for severity level."""
        return {
            Severity.CRITICAL: "🔴",
            Severity.HIGH: "🟠",
            Severity.MEDIUM: "🟡",
            Severity.LOW: "🔵",
            Severity.INFO: "⚪",
        }[self]
    
    @property
    def priority(self) -> int:
        """Return numeric priority (higher = more severe)."""
        return {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
        }[self]


@dataclass
class Finding:
    """Represents a security finding in the code."""
    
    rule_id: str
    rule_name: str
    severity: Severity
    filepath: str
    line_number: int
    column: Optional[int] = None
    code_snippet: str = ""
    message: str = ""
    fix_suggestion: str = ""
    context_before: List[str] = field(default_factory=list)
    context_after: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        """Convert finding to dictionary for JSON output."""
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity.value,
            "filepath": self.filepath,
            "line_number": self.line_number,
            "column": self.column,
            "code_snippet": self.code_snippet,
            "message": self.message,
            "fix_suggestion": self.fix_suggestion,
        }


class BasePattern(ABC):
    """Abstract base class for security pattern detectors."""
    
    # Subclasses must define these
    rule_id: str = ""
    name: str = ""
    description: str = ""
    severity: Severity = Severity.MEDIUM
    
    # File extensions this pattern applies to
    file_extensions: List[str] = [".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb"]
    
    def __init__(self):
        """Initialize the pattern detector."""
        if not self.rule_id:
            raise ValueError(f"{self.__class__.__name__} must define rule_id")
        if not self.name:
            raise ValueError(f"{self.__class__.__name__} must define name")
    
    def should_scan_file(self, filepath: str) -> bool:
        """Check if this pattern should scan the given file."""
        path = Path(filepath)
        return path.suffix.lower() in self.file_extensions
    
    @abstractmethod
    def scan(self, content: str, filepath: str) -> List[Finding]:
        """
        Scan content for security issues.
        
        Args:
            content: The file content to scan
            filepath: Path to the file being scanned
            
        Returns:
            List of findings
        """
        pass
    
    def _create_finding(
        self,
        filepath: str,
        line_number: int,
        code_snippet: str,
        message: str,
        fix_suggestion: str = "",
        column: Optional[int] = None,
    ) -> Finding:
        """Helper to create a Finding with common fields."""
        return Finding(
            rule_id=self.rule_id,
            rule_name=self.name,
            severity=self.severity,
            filepath=filepath,
            line_number=line_number,
            column=column,
            code_snippet=code_snippet.strip(),
            message=message,
            fix_suggestion=fix_suggestion,
        )
    
    def _get_line_number(self, content: str, position: int) -> int:
        """Get line number from character position."""
        return content[:position].count('\n') + 1
    
    def _get_line_at(self, content: str, line_number: int) -> str:
        """Get the content of a specific line."""
        lines = content.split('\n')
        if 1 <= line_number <= len(lines):
            return lines[line_number - 1]
        return ""
