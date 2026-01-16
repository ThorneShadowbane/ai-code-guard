"""Command-line interface for AI Code Guard Pro."""

from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console

from .models import Config, Severity
from .reporters import ConsoleReporter, get_reporter
from .scanner import Scanner


console = Console()


def load_config(config_path: Path | None) -> Config:
    """Load configuration from file or return defaults."""
    if config_path is None:
        # Try to find config in current directory
        for name in [".ai-code-guard.yaml", ".ai-code-guard.yml", "ai-code-guard.yaml"]:
            path = Path(name)
            if path.exists():
                config_path = path
                break
    
    if config_path is None or not config_path.exists():
        return Config()
    
    import yaml
    
    with open(config_path) as f:
        data = yaml.safe_load(f) or {}
    
    return Config.from_dict(data)


@click.group()
@click.version_option(version="1.0.0", prog_name="AI Code Guard Pro")
def main() -> None:
    """🛡️ AI Code Guard Pro - Security scanner for AI-generated code."""
    pass


@main.command()
@click.argument("path", type=click.Path(exists=True), default=".")
@click.option(
    "--format", "-f",
    type=click.Choice(["console", "json", "sarif", "markdown"]),
    default="console",
    help="Output format",
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    help="Output file (default: stdout)",
)
@click.option(
    "--severity", "-s",
    type=click.Choice(["critical", "high", "medium", "low", "info"]),
    default="low",
    help="Minimum severity to report",
)
@click.option(
    "--config", "-c",
    type=click.Path(exists=True),
    help="Configuration file path",
)
@click.option(
    "--ignore", "-i",
    multiple=True,
    help="Patterns to ignore (can be used multiple times)",
)
@click.option(
    "--disable-rule", "-d",
    multiple=True,
    help="Rule IDs to disable (can be used multiple times)",
)
@click.option(
    "--fail-on",
    type=click.Choice(["critical", "high", "medium", "low", "info", "never"]),
    default="high",
    help="Fail with non-zero exit code if issues at this severity or higher are found",
)
@click.option(
    "--parallel", "-p",
    type=int,
    default=4,
    help="Number of parallel workers",
)
@click.option(
    "--no-secrets",
    is_flag=True,
    help="Disable secret detection",
)
@click.option(
    "--no-prompt-injection",
    is_flag=True,
    help="Disable prompt injection detection",
)
def scan(
    path: str,
    format: str,
    output: str | None,
    severity: str,
    config: str | None,
    ignore: tuple[str, ...],
    disable_rule: tuple[str, ...],
    fail_on: str,
    parallel: int,
    no_secrets: bool,
    no_prompt_injection: bool,
) -> None:
    """Scan a file or directory for security issues."""
    # Load configuration
    cfg = load_config(Path(config) if config else None)
    
    # Override with CLI options
    cfg.min_severity = Severity[severity.upper()]
    cfg.ignore_patterns.extend(ignore)
    cfg.disabled_rules.update(disable_rule)
    cfg.parallel_workers = parallel
    cfg.detect_prompt_injection = not no_prompt_injection
    
    if no_secrets:
        # Disable all secret rules
        for i in range(1, 100):
            cfg.disabled_rules.add(f"SEC{i:03d}")
    
    # Run scan
    scanner = Scanner(cfg)
    
    if format == "console":
        console.print()
        console.print("[bold blue]🛡️  AI Code Guard Pro[/bold blue] [dim]v1.0.0[/dim]")
        console.print(f"   Scanning [cyan]{path}[/cyan]...")
        console.print()
    
    result = scanner.scan_path(Path(path))
    
    # Generate report
    reporter = get_reporter(format)
    report_output = reporter.report(result)
    
    # Write output
    if output:
        Path(output).write_text(report_output)
        if format == "console":
            console.print(f"[green]Report written to {output}[/green]")
    elif report_output:  # Console reporter returns empty string
        print(report_output)
    
    # Determine exit code
    if fail_on != "never":
        fail_severity = Severity[fail_on.upper()]
        if result.has_blocking_issues(fail_severity):
            sys.exit(1)


@main.command()
@click.argument("path", type=click.Path(exists=True))
def check(path: str) -> None:
    """Quick check with minimal output (for CI/CD)."""
    scanner = Scanner()
    result = scanner.scan_path(Path(path))
    
    if result.findings:
        critical = len(result.by_severity[Severity.CRITICAL])
        high = len(result.by_severity[Severity.HIGH])
        
        if critical > 0:
            console.print(f"[red]CRITICAL: {critical} issues found[/red]")
        if high > 0:
            console.print(f"[yellow]HIGH: {high} issues found[/yellow]")
        
        console.print(f"Total: {len(result.findings)} issues in {result.files_scanned} files")
        sys.exit(1)
    else:
        console.print(f"[green]✓ No issues found in {result.files_scanned} files[/green]")
        sys.exit(0)


@main.command()
def init() -> None:
    """Create a default configuration file."""
    config_content = """\
# AI Code Guard Pro Configuration

# Minimum severity to report (critical, high, medium, low, info)
min_severity: low

# Patterns to ignore
ignore:
  - "tests/**"
  - "**/test_*.py"
  - "**/*_test.py"
  - "examples/**"
  - "docs/**"

# Rules to disable (by rule ID)
disable_rules: []
  # - "SEC001"  # Hardcoded secrets (if using examples)
  # - "PRI001"  # Prompt injection (if false positives)

# Secret detection settings
entropy_threshold: 4.5
min_secret_length: 16

# AI-specific detection
detect_placeholder_secrets: true
detect_prompt_injection: true

# Performance
max_file_size_kb: 1024
parallel_workers: 4
"""
    
    config_path = Path(".ai-code-guard.yaml")
    
    if config_path.exists():
        console.print("[yellow]Configuration file already exists[/yellow]")
        return
    
    config_path.write_text(config_content)
    console.print(f"[green]Created {config_path}[/green]")


@main.command()
def rules() -> None:
    """List all available detection rules."""
    from rich.table import Table
    
    table = Table(title="AI Code Guard Pro Rules")
    table.add_column("Rule ID", style="cyan")
    table.add_column("Category", style="magenta")
    table.add_column("Severity", style="yellow")
    table.add_column("Description")
    
    # Add rules
    rules_data = [
        ("SEC001-015", "Secrets", "CRITICAL/HIGH", "API keys and tokens (OpenAI, AWS, GitHub, etc.)"),
        ("SEC020-022", "Secrets", "CRITICAL", "Private keys (RSA, SSH, PGP)"),
        ("SEC030-031", "Secrets", "CRITICAL/HIGH", "Database credentials and passwords"),
        ("SEC040", "Secrets", "MEDIUM", "JWT tokens"),
        ("SEC050", "Secrets", "MEDIUM", "AI placeholder secrets"),
        ("SEC099", "Secrets", "MEDIUM", "High-entropy strings"),
        ("INJ001", "Injection", "CRITICAL", "SQL injection"),
        ("INJ002", "Injection", "CRITICAL", "Command injection"),
        ("INJ003", "Injection", "CRITICAL", "Code execution (eval/exec)"),
        ("DES001", "Deserialization", "CRITICAL", "Unsafe YAML deserialization"),
        ("DES002", "Deserialization", "CRITICAL", "Unsafe pickle deserialization"),
        ("SSRF001", "SSRF", "HIGH/MEDIUM", "Server-side request forgery"),
        ("PRI001-005", "Prompt Injection", "HIGH/MEDIUM", "Direct prompt injection"),
        ("PRI006", "Prompt Injection", "MEDIUM", "User input in prompts"),
        ("PRI010-011", "Prompt Injection", "MEDIUM", "Indirect injection (RAG, web)"),
        ("DEP001", "Dependencies", "CRITICAL-MEDIUM", "Known suspicious packages"),
        ("DEP002", "Dependencies", "HIGH/MEDIUM", "Potential typosquatting"),
        ("DEP003", "Dependencies", "HIGH", "Dependency confusion risk"),
    ]
    
    for rule_id, category, severity, description in rules_data:
        table.add_row(rule_id, category, severity, description)
    
    console.print(table)


if __name__ == "__main__":
    main()
