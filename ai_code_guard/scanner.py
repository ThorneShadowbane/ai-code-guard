"""Main scanner engine that orchestrates all analyzers."""

from __future__ import annotations

import fnmatch
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Iterator

from .analyzers import (
    DependencyAnalyzer,
    IndirectInjectionAnalyzer,
    PromptInjectionAnalyzer,
    PythonASTAnalyzer,
    SecretsAnalyzer,
)
from .models import Config, Finding, ScanResult, Severity


# File extensions to scan
SCANNABLE_EXTENSIONS = {
    # Python
    ".py", ".pyw", ".pyi",
    # JavaScript/TypeScript
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    # Configuration
    ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg",
    # Other
    ".env", ".sh", ".bash", ".zsh",
    # Dependency files (no extension)
}

# Files to always scan regardless of extension
ALWAYS_SCAN_FILES = {
    "requirements.txt", "pyproject.toml", "setup.py", "setup.cfg",
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "Pipfile", "Pipfile.lock", "poetry.lock",
    ".env", ".env.local", ".env.production", ".env.development",
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
}

# Default ignore patterns
DEFAULT_IGNORE_PATTERNS = [
    "**/.git/**",
    "**/node_modules/**",
    "**/__pycache__/**",
    "**/.venv/**",
    "**/venv/**",
    "**/.env/**",
    "**/env/**",
    "**/.tox/**",
    "**/.mypy_cache/**",
    "**/.pytest_cache/**",
    "**/dist/**",
    "**/build/**",
    "**/*.egg-info/**",
    "**/.idea/**",
    "**/.vscode/**",
]


class Scanner:
    """
    Main security scanner that orchestrates all analyzers.
    
    Features:
    - Parallel file scanning
    - Configurable ignore patterns
    - Multiple output formats
    - Severity filtering
    """
    
    def __init__(self, config: Config | None = None):
        self.config = config or Config()
        self.ignore_patterns = DEFAULT_IGNORE_PATTERNS + self.config.ignore_patterns
    
    def scan_path(self, path: Path) -> ScanResult:
        """Scan a file or directory."""
        start_time = time.time()
        
        if path.is_file():
            files = [path]
        else:
            files = list(self._collect_files(path))
        
        # Run scans
        all_findings: list[Finding] = []
        errors: list[str] = []
        
        if self.config.parallel_workers > 1 and len(files) > 10:
            # Parallel scanning for large codebases
            all_findings, errors = self._scan_parallel(files)
        else:
            # Sequential scanning
            for filepath in files:
                try:
                    findings = self._scan_file(filepath)
                    all_findings.extend(findings)
                except Exception as e:
                    errors.append(f"Error scanning {filepath}: {e}")
        
        # Filter by severity
        filtered_findings = [
            f for f in all_findings
            if f.severity.value <= self.config.min_severity.value
        ]
        
        # Deduplicate findings
        seen_fingerprints: set[str] = set()
        unique_findings: list[Finding] = []
        for finding in filtered_findings:
            if finding.fingerprint not in seen_fingerprints:
                seen_fingerprints.add(finding.fingerprint)
                unique_findings.append(finding)
        
        # Sort by severity, then file, then line
        unique_findings.sort(key=lambda f: (f.severity.value, str(f.location.filepath), f.location.line))
        
        return ScanResult(
            findings=unique_findings,
            files_scanned=len(files),
            scan_duration_ms=(time.time() - start_time) * 1000,
            errors=errors,
        )
    
    def _collect_files(self, directory: Path) -> Iterator[Path]:
        """Recursively collect files to scan."""
        for item in directory.rglob("*"):
            if not item.is_file():
                continue
            
            # Check ignore patterns
            if self._should_ignore(item, directory):
                continue
            
            # Check if file should be scanned
            if self._should_scan(item):
                yield item
    
    def _should_ignore(self, filepath: Path, base: Path) -> bool:
        """Check if a file should be ignored."""
        try:
            relative = filepath.relative_to(base)
        except ValueError:
            relative = filepath
        
        relative_str = str(relative)
        
        for pattern in self.ignore_patterns:
            if fnmatch.fnmatch(relative_str, pattern):
                return True
            if fnmatch.fnmatch(str(filepath), pattern):
                return True
        
        # Skip hidden files unless configured
        if not self.config.scan_hidden and any(
            part.startswith('.') for part in filepath.parts
        ):
            return True
        
        return False
    
    def _should_scan(self, filepath: Path) -> bool:
        """Check if a file should be scanned."""
        # Always scan specific files
        if filepath.name in ALWAYS_SCAN_FILES:
            return True
        
        # Check extension
        if filepath.suffix.lower() in SCANNABLE_EXTENSIONS:
            return True
        
        # Check file size
        try:
            if filepath.stat().st_size > self.config.max_file_size_kb * 1024:
                return False
        except OSError:
            return False
        
        return False
    
    def _scan_file(self, filepath: Path) -> list[Finding]:
        """Scan a single file with all applicable analyzers."""
        try:
            content = filepath.read_text(encoding='utf-8', errors='replace')
        except Exception:
            return []
        
        findings: list[Finding] = []
        
        # Run secrets analyzer on all files
        secrets_analyzer = SecretsAnalyzer(filepath, content, self.config)
        findings.extend(secrets_analyzer.analyze())
        
        # Run dependency analyzer on dependency files
        if self._is_dependency_file(filepath):
            dep_analyzer = DependencyAnalyzer(filepath, content, self.config)
            findings.extend(dep_analyzer.analyze())
        
        # Run Python-specific analyzers
        if filepath.suffix in {".py", ".pyw", ".pyi"}:
            # AST analyzer for deep analysis
            ast_analyzer = PythonASTAnalyzer(filepath, content, self.config)
            findings.extend(ast_analyzer.analyze())
            
            # Prompt injection analyzer
            pi_analyzer = PromptInjectionAnalyzer(filepath, content, self.config)
            findings.extend(pi_analyzer.analyze())
            
            # Indirect injection analyzer
            indirect_analyzer = IndirectInjectionAnalyzer(filepath, content, self.config)
            findings.extend(indirect_analyzer.analyze())
        
        # Run prompt injection on JS/TS files too
        elif filepath.suffix in {".js", ".jsx", ".ts", ".tsx"}:
            pi_analyzer = PromptInjectionAnalyzer(filepath, content, self.config)
            findings.extend(pi_analyzer.analyze())
        
        return findings
    
    def _is_dependency_file(self, filepath: Path) -> bool:
        """Check if file is a dependency manifest."""
        return filepath.name.lower() in {
            "requirements.txt", "pyproject.toml", "setup.py", "pipfile",
            "package.json", "package-lock.json", "yarn.lock",
        }
    
    def _scan_parallel(self, files: list[Path]) -> tuple[list[Finding], list[str]]:
        """Scan files in parallel."""
        all_findings: list[Finding] = []
        errors: list[str] = []
        
        # Note: For true parallelism with ProcessPoolExecutor,
        # we'd need to make objects picklable. Using ThreadPoolExecutor instead.
        from concurrent.futures import ThreadPoolExecutor
        
        with ThreadPoolExecutor(max_workers=self.config.parallel_workers) as executor:
            future_to_file = {
                executor.submit(self._scan_file, f): f for f in files
            }
            
            for future in as_completed(future_to_file):
                filepath = future_to_file[future]
                try:
                    findings = future.result()
                    all_findings.extend(findings)
                except Exception as e:
                    errors.append(f"Error scanning {filepath}: {e}")
        
        return all_findings, errors


def scan(
    path: str | Path,
    config: Config | None = None,
) -> ScanResult:
    """Convenience function to scan a path."""
    scanner = Scanner(config)
    return scanner.scan_path(Path(path))
