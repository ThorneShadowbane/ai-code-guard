"""Command-line interface for AI Code Guard."""

import sys
from pathlib import Path

import click

from .scanner import Scanner, ScanConfig
from .reporters import ConsoleReporter, JSONReporter, SARIFReporter


@click.group()
@click.version_option(version="0.1.0", prog_name="ai-code-guard")
def main():
    """AI Code Guard - Detect security vulnerabilities in AI-generated code.
    
    Scans your codebase for security issues commonly found in code generated
    by AI assistants like GitHub Copilot, Claude, and ChatGPT.
    """
    pass


@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option(
    "--format", "-f",
    type=click.Choice(["console", "json", "sarif"]),
    default="console",
    help="Output format"
)
@click.option(
    "--config", "-c",
    type=click.Path(exists=True),
    help="Path to configuration file (.ai-code-guard.yaml)"
)
@click.option(
    "--min-severity",
    type=click.Choice(["critical", "high", "medium", "low", "info"]),
    default="low",
    help="Minimum severity to report"
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    help="Show verbose output including warnings"
)
@click.option(
    "--exit-code/--no-exit-code",
    default=True,
    help="Exit with non-zero code if issues found"
)
def scan(path: str, format: str, config: str, min_severity: str, verbose: bool, exit_code: bool):
    """Scan files or directories for security vulnerabilities.
    
    Examples:
    
        ai-code-guard scan ./src
        
        ai-code-guard scan ./main.py --format json
        
        ai-code-guard scan ./project --min-severity high
    """
    # Load configuration
    scan_path = Path(path)
    
    if config:
        scan_config = ScanConfig.from_file(Path(config))
    else:
        # Look for config in target directory
        config_path = scan_path / ".ai-code-guard.yaml" if scan_path.is_dir() else scan_path.parent / ".ai-code-guard.yaml"
        scan_config = ScanConfig.from_file(config_path)
    
    # Override min severity from CLI
    from .patterns import Severity
    scan_config.min_severity = Severity(min_severity)
    
    # Run scanner
    scanner = Scanner(config=scan_config)
    result = scanner.scan_path(scan_path)
    
    # Output results
    if format == "json":
        reporter = JSONReporter()
        click.echo(reporter.report(result))
    elif format == "sarif":
        reporter = SARIFReporter()
        click.echo(reporter.report(result))
    else:
        reporter = ConsoleReporter()
        reporter.report(result, verbose=verbose)
    
    # Exit code
    if exit_code and (result.has_critical or result.has_high):
        sys.exit(1)


@main.command()
def rules():
    """List all available detection rules."""
    from .patterns import get_all_patterns
    
    click.echo("\n📋 AI Code Guard Detection Rules\n")
    click.echo("=" * 70)
    
    for pattern_cls in get_all_patterns():
        pattern = pattern_cls()
        severity_emoji = {
            "critical": "🔴",
            "high": "🟠", 
            "medium": "🟡",
            "low": "🔵",
            "info": "⚪",
        }.get(pattern.severity.value, "⚪")
        
        click.echo(f"\n{severity_emoji} {pattern.rule_id}: {pattern.name}")
        click.echo(f"   Severity: {pattern.severity.value.upper()}")
        if pattern.description:
            # Wrap description
            desc = pattern.description
            if len(desc) > 60:
                desc = desc[:60] + "..."
            click.echo(f"   {desc}")
    
    click.echo("\n" + "=" * 70)
    click.echo(f"Total: {len(get_all_patterns())} rules\n")


@main.command()
@click.argument("path", type=click.Path())
def init(path: str):
    """Initialize configuration file in target directory.
    
    Creates a .ai-code-guard.yaml with default settings.
    """
    config_path = Path(path)
    if config_path.is_dir():
        config_path = config_path / ".ai-code-guard.yaml"
    
    if config_path.exists():
        if not click.confirm(f"{config_path} already exists. Overwrite?"):
            return
    
    default_config = """\
# AI Code Guard Configuration
# https://github.com/AnjaliGNair/ai-code-guard

# Minimum severity to report (critical, high, medium, low, info)
min_severity: low

# Patterns to ignore (glob patterns)
ignore:
  - "tests/*"
  - "*.test.py"
  - "*_test.py"
  - "test_*.py"
  - "examples/*"
  - "docs/*"
  - "*.md"

# Specific rules to disable (by rule ID)
disable_rules: []
  # - "SEC001"  # Hardcoded secrets
  # - "PRI003"  # Missing sanitization (too noisy)

# Custom patterns (advanced)
# custom_secrets:
#   - pattern: "my-company-api-[a-zA-Z0-9]+"
#     name: "Company API Key"
"""
    
    config_path.write_text(default_config)
    click.echo(f"✅ Created {config_path}")


if __name__ == "__main__":
    main()
