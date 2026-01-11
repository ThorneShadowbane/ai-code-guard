# Contributing to AI Code Guard

Thank you for your interest in contributing to AI Code Guard! This document provides guidelines for contributing.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/ai-code-guard.git`
3. Install development dependencies: `pip install -e ".[dev]"`
4. Create a branch: `git checkout -b feature/your-feature`

## Development Setup

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on Windows

# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest

# Run linting
ruff check .
black --check .
mypy ai_code_guard/
```

## Adding New Detection Patterns

The most valuable contributions are new security patterns. Here's how to add one:

### 1. Choose the Right Category

- `patterns/prompt_injection.py` - LLM/AI specific vulnerabilities
- `patterns/secrets.py` - Hardcoded credentials
- `patterns/injection.py` - SQL, command, path injection
- `patterns/data_exfiltration.py` - Data leakage risks

### 2. Create Your Pattern Class

```python
from .base import BasePattern, Finding, Severity

class MyNewPattern(BasePattern):
    """Detect my new security issue."""
    
    rule_id = "XXX001"  # Unique ID
    name = "My Security Issue"
    description = "Description of what this detects and why it's dangerous."
    severity = Severity.HIGH  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    
    def scan(self, content: str, filepath: str) -> list[Finding]:
        findings = []
        # Your detection logic here
        return findings
```

### 3. Register Your Pattern

Add to the appropriate `*_PATTERNS` list at the bottom of the file.

### 4. Write Tests

Add tests in `tests/test_scanner.py`:

```python
def test_my_new_pattern(self):
    scanner = Scanner()
    code = '''vulnerable code here'''
    
    temp_file = Path("/tmp/test.py")
    temp_file.write_text(code)
    
    findings = scanner.scan_file(temp_file)
    assert any(f.rule_id == "XXX001" for f in findings)
    
    temp_file.unlink()
```

## Pattern Guidelines

### Good Patterns

- Target **specific** vulnerability types
- Have **low false positive** rates
- Provide **actionable fix suggestions**
- Are **relevant to AI-generated code** specifically

### Avoid

- Overly broad patterns that flag too much
- Patterns without clear security implications
- Duplicating existing tools (Bandit, Semgrep) without AI-specific value

## Pull Request Process

1. Ensure tests pass: `pytest`
2. Ensure linting passes: `ruff check . && black --check .`
3. Update README.md if adding new rule categories
4. Describe the security issue your pattern detects
5. Include example vulnerable code

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help others learn

## Questions?

Open an issue for discussion before major changes.
