# 🛡️ AI Code Guard

> Detect security vulnerabilities in AI-generated code before they reach production

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Security Tool](https://img.shields.io/badge/security-tool-red.svg)]()

AI coding assistants (GitHub Copilot, Claude, ChatGPT, Cursor) are revolutionizing development — but they can introduce security vulnerabilities that slip past code review. **AI Code Guard** scans your codebase for security issues commonly found in AI-generated code.

## 🎯 What It Detects

| Category | Examples |
|----------|----------|
| **Prompt Injection Risks** | User input in system prompts, unsafe template rendering |
| **Hardcoded Secrets** | API keys, passwords, tokens in AI-suggested code |
| **Insecure Code Patterns** | SQL injection, command injection, path traversal |
| **Data Exfiltration Risks** | Suspicious outbound requests, data leakage patterns |
| **Dependency Confusion** | Typosquatting packages, suspicious imports |

## 🚀 Quick Start

```bash
# Install
pip install ai-code-guard

# Scan a directory
ai-code-guard scan ./src

# Scan a single file
ai-code-guard scan ./src/api/chat.py

# Output as JSON
ai-code-guard scan ./src --format json
```

## 📊 Example Output

```
$ ai-code-guard scan ./my-project

🔍 AI Code Guard v0.1.0
   Scanning 47 files...

┌─────────────────────────────────────────────────────────────────────┐
│ CRITICAL: SQL Injection Vulnerability                               │
├─────────────────────────────────────────────────────────────────────┤
│ File: src/db/queries.py, Line 42                                    │
│ Code: query = f"SELECT * FROM users WHERE id = {user_id}"          │
│                                                                     │
│ AI-generated code often uses f-strings for SQL queries.            │
│ Use parameterized queries instead.                                  │
│                                                                     │
│ ✅ Fix: cursor.execute("SELECT * FROM users WHERE id = ?", (id,))  │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│ HIGH: Prompt Injection Risk                                         │
├─────────────────────────────────────────────────────────────────────┤
│ File: src/api/chat.py, Line 23                                      │
│ Code: prompt = f"You are a helper. User says: {user_input}"        │
│                                                                     │
│ User input directly concatenated into LLM prompt.                   │
│ Attacker can inject malicious instructions.                         │
│                                                                     │
│ ✅ Fix: Sanitize input and use structured prompt templates          │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│ HIGH: Hardcoded API Key                                             │
├─────────────────────────────────────────────────────────────────────┤
│ File: src/config.py, Line 15                                        │
│ Code: api_key = "sk-proj-abc123..."                                 │
│                                                                     │
│ AI assistants often generate code with placeholder secrets          │
│ that developers forget to remove.                                   │
│                                                                     │
│ ✅ Fix: Use environment variables: os.environ.get("API_KEY")        │
└─────────────────────────────────────────────────────────────────────┘

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📊 SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   Files scanned:  47
   Issues found:   3
   
   🔴 CRITICAL:    1
   🟠 HIGH:        2
   🟡 MEDIUM:      0
   🔵 LOW:         0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

## 🔧 Configuration

Create `.ai-code-guard.yaml` in your project root:

```yaml
# Severity threshold (ignore issues below this level)
min_severity: medium

# Patterns to ignore
ignore:
  - "tests/*"
  - "*.test.py"
  - "examples/*"

# Specific rules to disable
disable_rules:
  - "SEC001"  # Hardcoded secrets (if using .env.example)

# Custom secret patterns to detect
custom_secrets:
  - pattern: "my-company-api-.*"
    name: "Company API Key"
```

## 📋 Rule Reference

| Rule ID | Category | Description |
|---------|----------|-------------|
| **SEC001** | Secrets | Hardcoded API keys, passwords, tokens |
| **SEC002** | Secrets | AWS/GCP/Azure credentials in code |
| **INJ001** | Injection | SQL injection via string formatting |
| **INJ002** | Injection | Command injection via os.system/subprocess |
| **INJ003** | Injection | Path traversal vulnerabilities |
| **PRI001** | Prompt Injection | User input in LLM system prompts |
| **PRI002** | Prompt Injection | Unsafe prompt template rendering |
| **PRI003** | Prompt Injection | Missing input sanitization for LLM |
| **DEP001** | Dependencies | Known typosquatting packages |
| **DEP002** | Dependencies | Suspicious import patterns |
| **EXF001** | Data Exfiltration | Outbound requests with sensitive data |
| **EXF002** | Data Exfiltration | Base64 encoding of sensitive variables |

## 🔌 CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  ai-code-guard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      - run: pip install ai-code-guard
      - run: ai-code-guard scan ./src --format sarif > results.sarif
      - uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
```

### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://ThorneShadowbane/ai-code-guard
    rev: v0.1.0
    hooks:
      - id: ai-code-guard
```

## 🧠 Why AI-Generated Code Needs Special Attention

AI coding assistants are trained on vast amounts of code — including insecure patterns. Common issues include:

1. **Outdated Security Practices**: Training data includes old, insecure code
2. **Placeholder Secrets**: AI generates realistic-looking API keys as examples
3. **Prompt Injection Blindspots**: Most training data predates LLM security concerns
4. **Context-Free Suggestions**: AI doesn't understand your security requirements

This tool specifically targets patterns commonly introduced by AI assistants.

## 🤝 Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Adding New Detection Patterns

```python
# ai_code_guard/patterns/my_pattern.py
from ai_code_guard.patterns.base import BasePattern, Finding, Severity

class MyCustomPattern(BasePattern):
    """Detect my custom security issue."""
    
    rule_id = "CUS001"
    name = "Custom Security Issue"
    severity = Severity.HIGH
    
    def scan(self, content: str, filepath: str) -> list[Finding]:
        findings = []
        # Your detection logic here
        return findings
```

## 📚 Research Background

This tool implements patterns identified in research on AI coding assistant security vulnerabilities. Key references:

- [AI Security Vulnerability Assessment Framework]([https://zenodo.org/records/YOUR_DOI](https://zenodo.org/records/17924763)) — Research on prompt injection and data exfiltration risks in AI coding assistants

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

- Security patterns informed by OWASP guidelines
- Prompt injection research from the AI security community
- Inspired by tools like Semgrep, Bandit, and GitLeaks

---

**Built with 🛡️ by security engineers who use AI coding assistants daily**
