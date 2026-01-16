"""Output reporters for different formats."""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .models import Finding, RuleDefinition, ScanResult, Severity


class Reporter(ABC):
    """Base class for output reporters."""
    
    @abstractmethod
    def report(self, result: ScanResult) -> str:
        """Generate report string."""
        pass


class ConsoleReporter(Reporter):
    """Rich console output reporter."""
    
    def __init__(self, console: Console | None = None):
        self.console = console or Console()
    
    def report(self, result: ScanResult) -> str:
        """Print to console and return empty string."""
        self._print_header()
        self._print_findings(result)
        self._print_summary(result)
        return ""
    
    def _print_header(self) -> None:
        self.console.print()
        self.console.print(
            "[bold blue]🛡️  AI Code Guard Pro[/bold blue] [dim]v1.0.0[/dim]"
        )
        self.console.print()
    
    def _print_findings(self, result: ScanResult) -> None:
        if not result.findings:
            self.console.print("[green]✓ No security issues found![/green]")
            return
        
        for finding in result.findings:
            self._print_finding(finding)
    
    def _print_finding(self, finding: Finding) -> None:
        # Create panel with finding details
        severity_color = finding.severity.color
        
        title = Text()
        title.append(f"{finding.severity.emoji} ", style=severity_color)
        title.append(f"{finding.severity.name}: ", style=severity_color)
        title.append(finding.title, style="bold")
        
        content = Text()
        content.append(f"📍 {finding.location}\n", style="dim")
        content.append(f"\n{finding.description}\n")
        
        if finding.code_snippet:
            content.append("\n")
            content.append("Code: ", style="bold")
            content.append(f"{finding.code_snippet}\n", style="dim")
        
        if finding.fix_suggestion:
            content.append("\n")
            content.append("✅ Fix: ", style="green bold")
            content.append(finding.fix_suggestion)
        
        if finding.cwe_id:
            content.append(f"\n\n[dim]CWE: {finding.cwe_id}[/dim]")
        
        panel = Panel(
            content,
            title=title,
            border_style=severity_color.split()[0],
            padding=(0, 1),
        )
        self.console.print(panel)
        self.console.print()
    
    def _print_summary(self, result: ScanResult) -> None:
        self.console.print("─" * 60)
        
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Metric", style="bold")
        table.add_column("Value")
        
        table.add_row("Files scanned", str(result.files_scanned))
        table.add_row("Issues found", str(len(result.findings)))
        table.add_row("Scan time", f"{result.scan_duration_ms:.0f}ms")
        
        self.console.print(table)
        self.console.print()
        
        # Severity breakdown
        by_severity = result.by_severity
        severity_parts = []
        for sev in Severity:
            count = len(by_severity[sev])
            if count > 0:
                severity_parts.append(f"{sev.emoji} {sev.name}: {count}")
        
        if severity_parts:
            self.console.print("  ".join(severity_parts))
        
        self.console.print("─" * 60)


class SARIFReporter(Reporter):
    """SARIF 2.1.0 format reporter for GitHub integration."""
    
    SARIF_VERSION = "2.1.0"
    SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
    
    def report(self, result: ScanResult) -> str:
        """Generate SARIF JSON output."""
        sarif = {
            "$schema": self.SCHEMA_URI,
            "version": self.SARIF_VERSION,
            "runs": [self._create_run(result)],
        }
        return json.dumps(sarif, indent=2)
    
    def _create_run(self, result: ScanResult) -> dict[str, Any]:
        # Collect unique rules
        rules_map: dict[str, RuleDefinition] = {}
        for finding in result.findings:
            if finding.rule_id not in rules_map:
                rules_map[finding.rule_id] = RuleDefinition(
                    rule_id=finding.rule_id,
                    name=finding.title,
                    description=finding.description,
                    severity=finding.severity,
                    category=finding.category,
                    cwe_ids=[finding.cwe_id] if finding.cwe_id else [],
                )
        
        return {
            "tool": {
                "driver": {
                    "name": "AI Code Guard Pro",
                    "version": "1.0.0",
                    "informationUri": "https://github.com/ai-code-guard-pro",
                    "rules": [r.to_sarif_rule() for r in rules_map.values()],
                }
            },
            "results": [f.to_sarif() for f in result.findings],
            "invocations": [{
                "executionSuccessful": len(result.errors) == 0,
                "toolExecutionNotifications": [
                    {"message": {"text": e}, "level": "error"}
                    for e in result.errors
                ],
            }],
        }


class JSONReporter(Reporter):
    """Simple JSON output reporter."""
    
    def report(self, result: ScanResult) -> str:
        output = {
            "summary": {
                "files_scanned": result.files_scanned,
                "issues_found": len(result.findings),
                "scan_duration_ms": result.scan_duration_ms,
                "by_severity": {
                    str(sev): len(findings)
                    for sev, findings in result.by_severity.items()
                },
            },
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "description": f.description,
                    "severity": str(f.severity),
                    "category": f.category.value,
                    "file": str(f.location.filepath),
                    "line": f.location.line,
                    "column": f.location.column,
                    "code_snippet": f.code_snippet,
                    "cwe_id": f.cwe_id,
                    "fix_suggestion": f.fix_suggestion,
                    "confidence": f.confidence,
                }
                for f in result.findings
            ],
            "errors": result.errors,
        }
        return json.dumps(output, indent=2)


class MarkdownReporter(Reporter):
    """Markdown format reporter for documentation/PRs."""
    
    def report(self, result: ScanResult) -> str:
        lines = [
            "# 🛡️ AI Code Guard Pro Security Report",
            "",
            f"**Scan Date:** {datetime.now(timezone.utc).isoformat()}",
            f"**Files Scanned:** {result.files_scanned}",
            f"**Issues Found:** {len(result.findings)}",
            "",
        ]
        
        if not result.findings:
            lines.append("✅ **No security issues found!**")
            return "\n".join(lines)
        
        # Summary table
        lines.extend([
            "## Summary",
            "",
            "| Severity | Count |",
            "|----------|-------|",
        ])
        
        for sev in Severity:
            count = len(result.by_severity[sev])
            if count > 0:
                lines.append(f"| {sev.emoji} {sev.name} | {count} |")
        
        lines.extend(["", "## Findings", ""])
        
        # Group by severity
        for sev in Severity:
            findings = result.by_severity[sev]
            if not findings:
                continue
            
            lines.append(f"### {sev.emoji} {sev.name}")
            lines.append("")
            
            for f in findings:
                lines.extend([
                    f"#### {f.title}",
                    "",
                    f"**Location:** `{f.location}`",
                    "",
                    f.description,
                    "",
                ])
                
                if f.code_snippet:
                    lines.extend([
                        "```",
                        f.code_snippet,
                        "```",
                        "",
                    ])
                
                if f.fix_suggestion:
                    lines.extend([
                        f"**Fix:** {f.fix_suggestion}",
                        "",
                    ])
                
                lines.append("---")
                lines.append("")
        
        return "\n".join(lines)


def get_reporter(format_name: str) -> Reporter:
    """Get reporter by format name."""
    reporters = {
        "console": ConsoleReporter,
        "sarif": SARIFReporter,
        "json": JSONReporter,
        "markdown": MarkdownReporter,
        "md": MarkdownReporter,
    }
    
    reporter_cls = reporters.get(format_name.lower())
    if reporter_cls is None:
        raise ValueError(f"Unknown format: {format_name}. Available: {list(reporters.keys())}")
    
    return reporter_cls()
