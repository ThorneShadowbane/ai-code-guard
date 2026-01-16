# 🛡️ AI Code Guard Pro

[![CI](https://github.com/ThorneShadowbane/ai-code-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/ThorneShadowbane/ai-code-guard/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

> **Industry-grade security scanner for AI-generated code** with AST analysis, taint tracking, and LLM-specific vulnerability detection.

AI coding assistants (GitHub Copilot, Claude, ChatGPT, Cursor) are revolutionizing development—but they can introduce security vulnerabilities that slip past code review. **AI Code Guard Pro** is a next-generation security scanner specifically designed to catch these issues.

## 🚀 Key Improvements Over Basic Scanners

| Feature | Basic Scanners | AI Code Guard Pro |
|---------|---------------|-------------------|
| **Analysis Method** | Regex matching | AST parsing + taint tracking |
| **False Positives** | High | Reduced via context awareness |
| **Secret Detection** | Pattern only | Pattern + Shannon entropy |
| **Prompt Injection** | ❌ Not detected | ✅ Direct + indirect detection |
| **Supply Chain** | Basic | Typosquatting + dependency confusion |
| **Output Formats** | Limited | Console, JSON, SARIF, Markdown |
| **CI/CD Integration** | Basic | Native SARIF for GitHub Security |

## 🎯 What It Detects

### 🔐 Secrets & Credentials
- **API Keys**: OpenAI, Anthropic, AWS, GCP, GitHub, Stripe, and 15+ providers
- **Private Keys**: RSA, SSH, PGP, EC
- **Database Credentials**: Connection strings, passwords
- **High-Entropy Strings**: AI placeholder secrets

### 💉 Injection Vulnerabilities
- **SQL Injection**: f-strings, .format(), concatenation in queries
- **Command Injection**: os.system, subprocess with shell=True
- **Code Execution**: eval(), exec() with user input
- **SSRF**: User-controlled URLs in requests

### 🤖 AI/LLM-Specific Issues
- **Direct Prompt Injection**: User input in system prompts
- **Indirect Injection**: RAG/retrieval injection risks
- **Unsafe Deserialization**: pickle, yaml.load without SafeLoader

### 📦 Supply Chain Attacks
- **Typosquatting**: Similar names to popular packages
- **Dependency Confusion**: Internal package name patterns
- **Known Malicious Packages**: Database of suspicious packages

## 📦 Installation

```bash
pip install ai-code-guard
```

Or with development dependencies:

```bash
pip install ai-code-guard[dev]
```

## 🔧 Quick Start

```bash
# Scan a directory
ai-code-guard scan ./src

# Scan with specific output format
ai-code-guard scan ./src --format sarif -o results.sarif

# Quick CI check
ai-code-guard check ./src

# List all rules
ai-code-guard rules

# Create config file
ai-code-guard init
```

## 📊 Example Output

```
🛡️  AI Code Guard Pro v1.0.0
   Scanning ./my-project...

┌─────────────────────────────────────────────────────────────────────┐
│ 🔴 CRITICAL: SQL Injection Vulnerability                            │
├─────────────────────────────────────────────────────────────────────┤
│ 📍 src/db/queries.py:42                                             │
│                                                                     │
│ SQL query constructed using f-string interpolation. User-controlled │
│ data may be interpolated directly into the query, enabling SQL      │
│ injection attacks.                                                  │
│                                                                     │
│ Code: query = f"SELECT * FROM users WHERE id = {user_id}"          │
│                                                                     │
│ ✅ Fix: Use parameterized queries:                                  │
│    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))  │
│                                                                     │
│ CWE: CWE-89                                                         │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│ 🟠 HIGH: Prompt Injection Vulnerability                             │
├─────────────────────────────────────────────────────────────────────┤
│ 📍 src/api/chat.py:23                                               │
│                                                                     │
│ User input directly embedded in LLM prompt via f-string. Attackers  │
│ can inject malicious instructions to manipulate the AI's behavior.  │
│                                                                     │
│ Code: prompt = f"You are a helper. User says: {user_input}"        │
│                                                                     │
│ ✅ Fix:                                                              │
│ 1. Separate system prompts from user content using message roles    │
│ 2. Sanitize user input (remove control characters, limit length)    │
│ 3. Use structured output formats to detect injection attempts       │
│                                                                     │
│ CWE: CWE-74 | OWASP: LLM01                                          │
└─────────────────────────────────────────────────────────────────────┘

────────────────────────────────────────────────────────────────────────
📊 SUMMARY
────────────────────────────────────────────────────────────────────────
Files scanned    47
Issues found     3
Scan time        127ms

🔴 CRITICAL: 1  🟠 HIGH: 2  🟡 MEDIUM: 0  🔵 LOW: 0
────────────────────────────────────────────────────────────────────────
```

## ⚙️ Configuration

Create `.ai-code-guard.yaml` in your project root:

```yaml
# Minimum severity to report
min_severity: low  # critical, high, medium, low, info

# Patterns to ignore
ignore:
  - "tests/**"
  - "**/test_*.py"
  - "examples/**"
  - "docs/**"

# Rules to disable
disable_rules: []
  # - "SEC001"  # If using example API keys
  # - "PRI001"  # If false positives on prompt construction

# Secret detection tuning
entropy_threshold: 4.5  # Shannon entropy threshold
min_secret_length: 16

# AI-specific detection
detect_placeholder_secrets: true
detect_prompt_injection: true

# Performance
max_file_size_kb: 1024
parallel_workers: 4
```

## 🔌 CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      
      - run: pip install ai-code-guard
      
      - name: Run security scan
        run: ai-code-guard scan . --format sarif -o results.sarif --fail-on high
      
      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v2
        if: always()
        with:
          sarif_file: results.sarif
```

### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: ai-code-guard
        name: AI Code Guard Security Scan
        entry: ai-code-guard check
        language: python
        types: [python]
        pass_filenames: false
```

### GitLab CI

```yaml
security-scan:
  image: python:3.11
  script:
    - pip install ai-code-guard
    - ai-code-guard scan . --format json -o gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
```

## 📋 Rule Reference

| Rule ID | Category | Severity | Description |
|---------|----------|----------|-------------|
| SEC001-015 | Secrets | CRITICAL/HIGH | API keys (OpenAI, AWS, GitHub, Stripe, etc.) |
| SEC020-022 | Secrets | CRITICAL | Private keys (RSA, SSH, PGP) |
| SEC030-031 | Secrets | CRITICAL | Database credentials |
| SEC040 | Secrets | MEDIUM | JWT tokens |
| SEC050 | Secrets | MEDIUM | AI placeholder secrets |
| SEC099 | Secrets | MEDIUM | High-entropy strings |
| INJ001 | Injection | CRITICAL | SQL injection |
| INJ002 | Injection | CRITICAL | Command injection |
| INJ003 | Injection | CRITICAL | Code execution (eval/exec) |
| DES001 | Deserialization | CRITICAL | Unsafe YAML |
| DES002 | Deserialization | CRITICAL | Unsafe pickle |
| SSRF001 | SSRF | HIGH | Server-side request forgery |
| PRI001-005 | Prompt Injection | HIGH | Direct prompt injection |
| PRI006 | Prompt Injection | MEDIUM | User input in prompts |
| PRI010-011 | Prompt Injection | MEDIUM | Indirect injection |
| DEP001 | Dependencies | VARIES | Known suspicious packages |
| DEP002 | Dependencies | HIGH | Typosquatting detection |
| DEP003 | Dependencies | HIGH | Dependency confusion |

## 🔬 Technical Details

### AST-Based Analysis

Unlike regex-based scanners, AI Code Guard Pro parses Python code into an Abstract Syntax Tree, enabling:

- **Taint tracking**: Follow user input through variable assignments
- **Context awareness**: Understand function calls and their arguments
- **Reduced false positives**: Skip patterns in comments and strings

### Entropy-Based Secret Detection

Uses Shannon entropy to distinguish real secrets from placeholders:

```python
# High entropy (likely real secret) - DETECTED
api_key = "sk-proj-aB3xK9mL2pQrStUvWxYz..."

# Low entropy (placeholder) - IGNORED
api_key = "your-api-key-here"
```

### LLM Security Focus

Specifically targets vulnerabilities in AI/LLM applications:

- Detects prompt injection in OpenAI, Anthropic, and LangChain code
- Identifies indirect injection risks in RAG pipelines
- Flags unsafe patterns in agent/tool implementations

## 🤝 Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Adding Detection Patterns

```python
# ai_code_guard_pro/analyzers/my_analyzer.py
from ai_code_guard_pro.models import Finding, Severity, Category

class MyAnalyzer:
    def analyze(self) -> list[Finding]:
        findings = []
        # Your detection logic
        return findings
```

## 📚 References

- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [CWE - Common Weakness Enumeration](https://cwe.mitre.org/)
- [SARIF Specification](https://sarifweb.azurewebsites.net/)

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

---

**Built for the AI era by security engineers who use AI coding assistants daily** 🛡️
