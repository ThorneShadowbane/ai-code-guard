"""Advanced secret detection with entropy analysis and pattern matching."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from ..models import Category, Config, Finding, Location, Severity


@dataclass
class SecretPattern:
    """Definition of a secret pattern to detect."""
    
    rule_id: str
    name: str
    pattern: re.Pattern[str]
    severity: Severity
    description: str
    fix_suggestion: str
    cwe_id: str = "CWE-798"
    min_entropy: float | None = None  # Optional entropy threshold
    false_positive_patterns: list[re.Pattern[str]] | None = None
    
    def __post_init__(self) -> None:
        if self.false_positive_patterns is None:
            self.false_positive_patterns = []


# Industry-standard secret patterns based on GitLeaks, TruffleHog, and security research
SECRET_PATTERNS: list[SecretPattern] = [
    # === API Keys ===
    SecretPattern(
        rule_id="SEC001",
        name="OpenAI API Key",
        pattern=re.compile(r'sk-[a-zA-Z0-9]{20,}T3BlbkFJ[a-zA-Z0-9]{20,}'),
        severity=Severity.CRITICAL,
        description="OpenAI API key detected. These keys provide access to paid AI services.",
        fix_suggestion="Use environment variables: os.environ.get('OPENAI_API_KEY')",
    ),
    SecretPattern(
        rule_id="SEC001",
        name="OpenAI Project API Key",
        pattern=re.compile(r'sk-proj-[a-zA-Z0-9_-]{80,}'),
        severity=Severity.CRITICAL,
        description="OpenAI project API key detected.",
        fix_suggestion="Use environment variables: os.environ.get('OPENAI_API_KEY')",
    ),
    SecretPattern(
        rule_id="SEC002",
        name="Anthropic API Key",
        pattern=re.compile(r'sk-ant-api\d{2}-[a-zA-Z0-9_-]{80,}'),
        severity=Severity.CRITICAL,
        description="Anthropic API key detected. These keys provide access to Claude AI services.",
        fix_suggestion="Use environment variables: os.environ.get('ANTHROPIC_API_KEY')",
    ),
    SecretPattern(
        rule_id="SEC003",
        name="AWS Access Key ID",
        pattern=re.compile(r'(?<![A-Z0-9])(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])'),
        severity=Severity.CRITICAL,
        description="AWS Access Key ID detected. Combined with secret key, provides AWS access.",
        fix_suggestion="Use AWS IAM roles, instance profiles, or environment variables",
    ),
    SecretPattern(
        rule_id="SEC004",
        name="AWS Secret Access Key",
        pattern=re.compile(r'(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])'),
        severity=Severity.CRITICAL,
        description="Potential AWS Secret Access Key detected (40-char base64).",
        fix_suggestion="Use AWS IAM roles or environment variables",
        min_entropy=4.5,  # Require high entropy to reduce false positives
    ),
    SecretPattern(
        rule_id="SEC005",
        name="Google Cloud API Key",
        pattern=re.compile(r'AIza[0-9A-Za-z_-]{35}'),
        severity=Severity.HIGH,
        description="Google Cloud API key detected.",
        fix_suggestion="Use service accounts and environment variables",
    ),
    SecretPattern(
        rule_id="SEC006",
        name="Google OAuth Client Secret",
        pattern=re.compile(r'GOCSPX-[a-zA-Z0-9_-]{28}'),
        severity=Severity.HIGH,
        description="Google OAuth client secret detected.",
        fix_suggestion="Store in secure secret management system",
    ),
    SecretPattern(
        rule_id="SEC007",
        name="GitHub Token",
        pattern=re.compile(r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}'),
        severity=Severity.CRITICAL,
        description="GitHub personal access token or app token detected.",
        fix_suggestion="Use GitHub Actions secrets or environment variables",
    ),
    SecretPattern(
        rule_id="SEC008",
        name="Slack Token",
        pattern=re.compile(r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*'),
        severity=Severity.HIGH,
        description="Slack API token detected.",
        fix_suggestion="Use environment variables and rotate the token",
    ),
    SecretPattern(
        rule_id="SEC009",
        name="Stripe API Key",
        pattern=re.compile(r'(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}'),
        severity=Severity.CRITICAL,
        description="Stripe API key detected. Live keys can access payment data.",
        fix_suggestion="Use environment variables. Never commit live keys.",
    ),
    SecretPattern(
        rule_id="SEC010",
        name="Twilio API Key",
        pattern=re.compile(r'SK[0-9a-fA-F]{32}'),
        severity=Severity.HIGH,
        description="Twilio API key detected.",
        fix_suggestion="Use environment variables",
    ),
    SecretPattern(
        rule_id="SEC011",
        name="SendGrid API Key",
        pattern=re.compile(r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}'),
        severity=Severity.HIGH,
        description="SendGrid API key detected.",
        fix_suggestion="Use environment variables",
    ),
    SecretPattern(
        rule_id="SEC012",
        name="Mailchimp API Key",
        pattern=re.compile(r'[0-9a-f]{32}-us[0-9]{1,2}'),
        severity=Severity.MEDIUM,
        description="Mailchimp API key detected.",
        fix_suggestion="Use environment variables",
    ),
    SecretPattern(
        rule_id="SEC013",
        name="Discord Bot Token",
        pattern=re.compile(r'[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}'),
        severity=Severity.HIGH,
        description="Discord bot token detected.",
        fix_suggestion="Use environment variables and regenerate the token",
    ),
    SecretPattern(
        rule_id="SEC014",
        name="npm Access Token",
        pattern=re.compile(r'npm_[A-Za-z0-9]{36}'),
        severity=Severity.HIGH,
        description="npm access token detected. Can publish packages.",
        fix_suggestion="Use npm automation tokens in CI/CD secrets",
    ),
    SecretPattern(
        rule_id="SEC015",
        name="PyPI API Token",
        pattern=re.compile(r'pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}'),
        severity=Severity.HIGH,
        description="PyPI API token detected. Can publish Python packages.",
        fix_suggestion="Use trusted publishing or CI/CD secrets",
    ),
    
    # === Private Keys ===
    SecretPattern(
        rule_id="SEC020",
        name="RSA Private Key",
        pattern=re.compile(r'-----BEGIN (?:RSA )?PRIVATE KEY-----'),
        severity=Severity.CRITICAL,
        description="Private key detected in source code.",
        fix_suggestion="Never commit private keys. Use secret management systems.",
        cwe_id="CWE-321",
    ),
    SecretPattern(
        rule_id="SEC021",
        name="SSH Private Key",
        pattern=re.compile(r'-----BEGIN (?:OPENSSH|EC|DSA) PRIVATE KEY-----'),
        severity=Severity.CRITICAL,
        description="SSH/EC/DSA private key detected.",
        fix_suggestion="Never commit private keys. Use SSH agent or secret management.",
        cwe_id="CWE-321",
    ),
    SecretPattern(
        rule_id="SEC022",
        name="PGP Private Key",
        pattern=re.compile(r'-----BEGIN PGP PRIVATE KEY BLOCK-----'),
        severity=Severity.CRITICAL,
        description="PGP private key detected.",
        fix_suggestion="Never commit private keys to source control.",
        cwe_id="CWE-321",
    ),
    
    # === Database Credentials ===
    SecretPattern(
        rule_id="SEC030",
        name="Database Connection String",
        pattern=re.compile(
            r'(?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis|mssql)://[^:]+:[^@]+@[^\s\'"]+',
            re.IGNORECASE
        ),
        severity=Severity.CRITICAL,
        description="Database connection string with credentials detected.",
        fix_suggestion="Use environment variables for database URLs",
    ),
    SecretPattern(
        rule_id="SEC031",
        name="Generic Password Assignment",
        pattern=re.compile(
            r'(?:password|passwd|pwd|secret|token|api_key|apikey)\s*[=:]\s*["\'][^"\']{8,}["\']',
            re.IGNORECASE
        ),
        severity=Severity.HIGH,
        description="Hardcoded password or secret assignment detected.",
        fix_suggestion="Use environment variables or secret management",
        min_entropy=3.0,  # Require some entropy
        false_positive_patterns=[
            re.compile(r'["\'](?:changeme|password|secret|example|placeholder|xxx|your[_-]?|test)["\']', re.IGNORECASE),
            re.compile(r'os\.(?:environ|getenv)'),
            re.compile(r'\.env'),
        ],
    ),
    
    # === JWT Tokens ===
    SecretPattern(
        rule_id="SEC040",
        name="JWT Token",
        pattern=re.compile(r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'),
        severity=Severity.MEDIUM,
        description="JWT token detected. May contain sensitive claims.",
        fix_suggestion="Don't hardcode JWT tokens. Generate them dynamically.",
    ),
    
    # === AI-Specific: Placeholder Secrets ===
    SecretPattern(
        rule_id="SEC050",
        name="AI Placeholder API Key",
        pattern=re.compile(
            r'["\'](?:sk[-_])?(?:api[-_]?key[-_]?)?[a-z0-9]{20,}["\']',
            re.IGNORECASE
        ),
        severity=Severity.MEDIUM,
        description="Potential placeholder API key generated by AI assistant. "
                   "AI coding tools often generate realistic-looking fake credentials.",
        fix_suggestion="Replace with environment variable reference",
        min_entropy=3.5,
        false_positive_patterns=[
            re.compile(r'test|example|placeholder|dummy|fake|mock', re.IGNORECASE),
        ],
    ),
]


def calculate_shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    
    # Count character frequencies
    freq: dict[str, int] = {}
    for char in data:
        freq[char] = freq.get(char, 0) + 1
    
    # Calculate entropy
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        if count > 0:
            probability = count / length
            entropy -= probability * math.log2(probability)
    
    return entropy


class SecretsAnalyzer:
    """
    Advanced secrets detection with entropy analysis.
    
    Improvements over basic regex matching:
    - Shannon entropy analysis to reduce false positives
    - Context-aware filtering (comments, test files, etc.)
    - False positive pattern exclusion
    - AI placeholder detection
    """
    
    def __init__(self, filepath: Path, content: str, config: Config):
        self.filepath = filepath
        self.content = content
        self.lines = content.splitlines()
        self.config = config
        
        # Additional false positive indicators
        self.fp_indicators = [
            "example", "placeholder", "changeme", "your_", "xxx",
            "test", "mock", "fake", "dummy", "sample",
        ]
    
    def analyze(self) -> list[Finding]:
        """Run secret detection."""
        findings: list[Finding] = []
        
        # Skip test files if configured
        if self._is_test_file():
            return findings
        
        for pattern in SECRET_PATTERNS:
            if pattern.rule_id in self.config.disabled_rules:
                continue
            
            findings.extend(self._scan_pattern(pattern))
        
        # Additional high-entropy string detection
        if self.config.detect_placeholder_secrets:
            findings.extend(self._detect_high_entropy_strings())
        
        return findings
    
    def _is_test_file(self) -> bool:
        """Check if this is a test file."""
        name = self.filepath.name.lower()
        path_str = str(self.filepath).lower()
        return (
            name.startswith("test_") or
            name.endswith("_test.py") or
            "/tests/" in path_str or
            "/test/" in path_str or
            "fixture" in name
        )
    
    def _scan_pattern(self, pattern: SecretPattern) -> Iterator[Finding]:
        """Scan for a specific secret pattern."""
        for line_num, line in enumerate(self.lines, start=1):
            for match in pattern.pattern.finditer(line):
                secret_value = match.group(0)
                
                # Skip if it's in a comment (basic detection)
                if self._is_in_comment(line, match.start()):
                    continue
                
                # Skip if matches false positive patterns
                if self._is_false_positive(pattern, line, secret_value):
                    continue
                
                # Check entropy threshold if specified
                if pattern.min_entropy is not None:
                    entropy = calculate_shannon_entropy(secret_value)
                    if entropy < pattern.min_entropy:
                        continue
                
                yield Finding(
                    rule_id=pattern.rule_id,
                    title=pattern.name,
                    description=pattern.description,
                    severity=pattern.severity,
                    category=Category.SECRETS,
                    location=Location(
                        filepath=self.filepath,
                        line=line_num,
                        column=match.start(),
                        end_column=match.end(),
                    ),
                    code_snippet=self._mask_secret(line, match.start(), match.end()),
                    cwe_id=pattern.cwe_id,
                    fix_suggestion=pattern.fix_suggestion,
                    metadata={"entropy": calculate_shannon_entropy(secret_value)},
                )
    
    def _is_in_comment(self, line: str, pos: int) -> bool:
        """Check if a position is inside a comment."""
        # Python single-line comment
        hash_pos = line.find('#')
        if hash_pos != -1 and hash_pos < pos:
            return True
        
        # JavaScript/TypeScript single-line comment
        double_slash = line.find('//')
        if double_slash != -1 and double_slash < pos:
            return True
        
        return False
    
    def _is_false_positive(
        self, pattern: SecretPattern, line: str, secret: str
    ) -> bool:
        """Check if a match is likely a false positive."""
        line_lower = line.lower()
        secret_lower = secret.lower()
        
        # Check built-in false positive patterns
        if pattern.false_positive_patterns:
            for fp_pattern in pattern.false_positive_patterns:
                if fp_pattern.search(line):
                    return True
        
        # Check common false positive indicators
        for indicator in self.fp_indicators:
            if indicator in secret_lower or indicator in line_lower:
                return True
        
        # Environment variable reference
        if "os.environ" in line or "os.getenv" in line or "process.env" in line:
            return True
        
        # Assignment to environment variable
        if ".env" in line.lower():
            return True
        
        return False
    
    def _mask_secret(self, line: str, start: int, end: int) -> str:
        """Mask the secret in the code snippet for safe display."""
        secret = line[start:end]
        if len(secret) > 8:
            masked = secret[:4] + "*" * (len(secret) - 8) + secret[-4:]
        else:
            masked = "*" * len(secret)
        return line[:start] + masked + line[end:]
    
    def _detect_high_entropy_strings(self) -> Iterator[Finding]:
        """Detect high-entropy strings that might be secrets."""
        # Pattern for quoted strings that look like secrets
        string_pattern = re.compile(r'["\']([A-Za-z0-9+/=_-]{20,})["\']')
        
        for line_num, line in enumerate(self.lines, start=1):
            # Skip comments
            if line.strip().startswith(('#', '//', '/*', '*')):
                continue
            
            for match in string_pattern.finditer(line):
                value = match.group(1)
                entropy = calculate_shannon_entropy(value)
                
                # High entropy threshold for generic detection
                if entropy < self.config.entropy_threshold:
                    continue
                
                # Skip if too long (likely encoded data, not a secret)
                if len(value) > 200:
                    continue
                
                # Skip if matches common patterns that aren't secrets
                if self._is_likely_not_secret(value, line):
                    continue
                
                yield Finding(
                    rule_id="SEC099",
                    title="High-Entropy String",
                    description=f"High-entropy string detected (entropy: {entropy:.2f}). "
                               f"This may be a hardcoded secret or API key.",
                    severity=Severity.MEDIUM,
                    category=Category.SECRETS,
                    location=Location(
                        filepath=self.filepath,
                        line=line_num,
                        column=match.start(),
                    ),
                    code_snippet=self._mask_secret(line, match.start(1), match.end(1)),
                    confidence=min(0.5 + (entropy - 4.0) * 0.1, 0.9),
                    metadata={"entropy": entropy},
                )
    
    def _is_likely_not_secret(self, value: str, line: str) -> bool:
        """Additional heuristics to filter non-secrets."""
        line_lower = line.lower()
        
        # UUIDs
        if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', value, re.I):
            return True
        
        # Hashes (likely intentional, not secrets)
        if any(x in line_lower for x in ['hash', 'checksum', 'sha', 'md5', 'digest']):
            return True
        
        # Base64 encoded images
        if any(x in line_lower for x in ['base64', 'data:image', 'data:application']):
            return True
        
        # URLs/paths that happen to have high entropy
        if value.startswith(('http', '/', './')):
            return True
        
        return False
