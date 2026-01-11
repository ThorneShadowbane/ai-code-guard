"""Output formatters for scan results."""

import json
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..patterns import Finding, Severity
from ..scanner import ScanResult


class ConsoleReporter:
    """Rich console output for scan results."""
    
    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console()
    
    def report(self, result: ScanResult, verbose: bool = False) -> None:
        """Print scan results to console."""
        # Header
        self.console.print()
        self.console.print(
            "[bold blue]🔍 AI Code Guard[/bold blue] v0.1.0",
            style="bold"
        )
        self.console.print(f"   Scanning {result.files_scanned} files...\n")
        
        if not result.findings:
            self.console.print(
                Panel(
                    "[green]✅ No security issues found![/green]",
                    title="Scan Complete",
                    border_style="green"
                )
            )
            return
        
        # Print each finding
        for finding in result.findings:
            self._print_finding(finding)
        
        # Summary
        self._print_summary(result)
        
        # Errors if any
        if result.errors and verbose:
            self.console.print("\n[yellow]Warnings:[/yellow]")
            for error in result.errors:
                self.console.print(f"  ⚠️  {error}")
    
    def _print_finding(self, finding: Finding) -> None:
        """Print a single finding as a panel."""
        # Severity styling
        severity_styles = {
            Severity.CRITICAL: ("red", "🔴 CRITICAL"),
            Severity.HIGH: ("orange1", "🟠 HIGH"),
            Severity.MEDIUM: ("yellow", "🟡 MEDIUM"),
            Severity.LOW: ("blue", "🔵 LOW"),
            Severity.INFO: ("white", "⚪ INFO"),
        }
        
        style, label = severity_styles.get(finding.severity, ("white", "INFO"))
        
        # Build content
        content = Text()
        content.append(f"File: ", style="dim")
        content.append(f"{finding.filepath}", style="cyan")
        content.append(f", Line {finding.line_number}\n", style="dim")
        content.append(f"Code: ", style="dim")
        content.append(f"{finding.code_snippet[:100]}", style="white")
        if len(finding.code_snippet) > 100:
            content.append("...", style="dim")
        content.append("\n\n")
        content.append(finding.message, style="white")
        
        if finding.fix_suggestion:
            content.append("\n\n")
            content.append("✅ Fix: ", style="green bold")
            content.append(finding.fix_suggestion, style="green")
        
        self.console.print(Panel(
            content,
            title=f"{label}: {finding.rule_name}",
            title_align="left",
            border_style=style,
            padding=(1, 2),
        ))
        self.console.print()
    
    def _print_summary(self, result: ScanResult) -> None:
        """Print scan summary."""
        counts = result.count_by_severity()
        
        self.console.print("━" * 70)
        self.console.print("[bold]📊 SUMMARY[/bold]")
        self.console.print("━" * 70)
        
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Label", style="dim")
        table.add_column("Value", style="bold")
        
        table.add_row("Files scanned:", str(result.files_scanned))
        table.add_row("Issues found:", str(result.total_issues))
        table.add_row("", "")
        table.add_row("🔴 CRITICAL:", str(counts[Severity.CRITICAL]))
        table.add_row("🟠 HIGH:", str(counts[Severity.HIGH]))
        table.add_row("🟡 MEDIUM:", str(counts[Severity.MEDIUM]))
        table.add_row("🔵 LOW:", str(counts[Severity.LOW]))
        
        self.console.print(table)
        self.console.print("━" * 70)


class JSONReporter:
    """JSON output for scan results."""
    
    def report(self, result: ScanResult) -> str:
        """Return scan results as JSON string."""
        output = {
            "summary": {
                "files_scanned": result.files_scanned,
                "files_skipped": result.files_skipped,
                "total_issues": result.total_issues,
                "by_severity": {
                    s.value: count 
                    for s, count in result.count_by_severity().items()
                },
            },
            "findings": [f.to_dict() for f in result.findings],
            "errors": result.errors,
        }
        return json.dumps(output, indent=2)


class SARIFReporter:
    """SARIF format output for GitHub Code Scanning integration."""
    
    SARIF_VERSION = "2.1.0"
    TOOL_NAME = "ai-code-guard"
    TOOL_VERSION = "0.1.0"
    
    def report(self, result: ScanResult) -> str:
        """Return scan results as SARIF JSON string."""
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": self.SARIF_VERSION,
            "runs": [{
                "tool": {
                    "driver": {
                        "name": self.TOOL_NAME,
                        "version": self.TOOL_VERSION,
                        "informationUri": "https://github.com/AnjaliGNair/ai-code-guard",
                        "rules": self._get_rules(result),
                    }
                },
                "results": self._get_results(result),
            }]
        }
        return json.dumps(sarif, indent=2)
    
    def _get_rules(self, result: ScanResult) -> list:
        """Extract unique rules from findings."""
        rules = {}
        for finding in result.findings:
            if finding.rule_id not in rules:
                rules[finding.rule_id] = {
                    "id": finding.rule_id,
                    "name": finding.rule_name,
                    "shortDescription": {"text": finding.rule_name},
                    "defaultConfiguration": {
                        "level": self._severity_to_sarif_level(finding.severity)
                    },
                }
        return list(rules.values())
    
    def _get_results(self, result: ScanResult) -> list:
        """Convert findings to SARIF results."""
        return [
            {
                "ruleId": f.rule_id,
                "level": self._severity_to_sarif_level(f.severity),
                "message": {"text": f.message},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.filepath},
                        "region": {
                            "startLine": f.line_number,
                            "startColumn": f.column or 1,
                        }
                    }
                }],
            }
            for f in result.findings
        ]
    
    def _severity_to_sarif_level(self, severity: Severity) -> str:
        """Convert severity to SARIF level."""
        mapping = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "note",
        }
        return mapping.get(severity, "note")
