# Contributing to AI Code Guard

Thank you for your interest in contributing to AI Code Guard! 🛡️

## How to Contribute

### Reporting Bugs

1. Check if the issue already exists in [Issues](https://github.com/ThorneShadowbane/ai-code-guard/issues)
2. Create a new issue with:
   - Clear description of the bug
   - Steps to reproduce
   - Expected vs actual behavior
   - Python version and OS

### Suggesting Features

Open an issue with:
- Description of the feature
- Use case / why it's needed
- Example of how it would work

### Submitting Code

1. Fork the repository
2. Create a branch: `git checkout -b feature/your-feature`
3. Make your changes
4. Test locally: `pip install -e . && ai-code-guard scan .`
5. Commit: `git commit -m "Add your feature"`
6. Push: `git push origin feature/your-feature`
7. Open a Pull Request

### Adding New Detection Rules

Create a new analyzer in `ai_code_guard/analyzers/`:
```python
from ai_code_guard.models import Finding, Severity, Category, Location

class MyAnalyzer:
    def __init__(self, filepath, content, config):
        self.filepath = filepath
        self.content = content
        self.config = config

    def analyze(self):
        findings = []
        # Your detection logic here
        return findings
```

Then register it in `ai_code_guard/scanner.py`.

## Code Style

- Use Python 3.10+ features
- Follow PEP 8
- Add type hints
- Keep functions small and focused

## Questions?

Open an issue or reach out to the maintainers.

Thanks for contributing! 🙏
