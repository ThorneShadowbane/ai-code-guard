"""Hardcoded secrets detection patterns.

AI coding assistants often generate code with placeholder API keys,
passwords, and tokens that developers forget to remove before committing.
"""

import re
from typing import List, Tuple

from .base import BasePattern, Finding, Severity


class HardcodedSecretsPattern(BasePattern):
    """Detect hardcoded API keys, passwords, and tokens."""
    
    rule_id = "SEC001"
    name = "Hardcoded Secret"
    description = (
        "Hardcoded secret detected in source code. "
        "AI assistants often generate realistic-looking placeholder secrets."
    )
    severity = Severity.HIGH
    
    # Patterns: (regex, secret_type, is_high_confidence)
    SECRET_PATTERNS: List[Tuple[str, str, bool]] = [
        # OpenAI
        (r'sk-[a-zA-Z0-9]{20,}', "OpenAI API Key", True),
        (r'sk-proj-[a-zA-Z0-9]{20,}', "OpenAI Project API Key", True),
        
        # Anthropic
        (r'sk-ant-[a-zA-Z0-9]{20,}', "Anthropic API Key", True),
        
        # AWS
        (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID", True),
        (r'(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])', "AWS Secret Key (potential)", False),
        
        # Google Cloud
        (r'AIza[0-9A-Za-z-_]{35}', "Google API Key", True),
        
        # GitHub
        (r'ghp_[a-zA-Z0-9]{36}', "GitHub Personal Access Token", True),
        (r'github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}', "GitHub Fine-grained PAT", True),
        (r'gho_[a-zA-Z0-9]{36}', "GitHub OAuth Token", True),
        (r'ghs_[a-zA-Z0-9]{36}', "GitHub Server Token", True),
        
        # Stripe
        (r'sk_live_[a-zA-Z0-9]{24,}', "Stripe Live Secret Key", True),
        (r'sk_test_[a-zA-Z0-9]{24,}', "Stripe Test Secret Key", True),
        (r'pk_live_[a-zA-Z0-9]{24,}', "Stripe Live Public Key", True),
        
        # Slack
        (r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*', "Slack Token", True),
        
        # Twilio
        (r'SK[a-f0-9]{32}', "Twilio API Key", True),
        
        # SendGrid
        (r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}', "SendGrid API Key", True),
        
        # Mailgun
        (r'key-[a-f0-9]{32}', "Mailgun API Key", True),
        
        # Generic patterns (lower confidence)
        (r'["\']?api[_-]?key["\']?\s*[:=]\s*["\'][a-zA-Z0-9_-]{20,}["\']', "Generic API Key", False),
        (r'["\']?secret[_-]?key["\']?\s*[:=]\s*["\'][a-zA-Z0-9_-]{20,}["\']', "Generic Secret Key", False),
        (r'["\']?auth[_-]?token["\']?\s*[:=]\s*["\'][a-zA-Z0-9_-]{20,}["\']', "Generic Auth Token", False),
        (r'["\']?access[_-]?token["\']?\s*[:=]\s*["\'][a-zA-Z0-9_-]{20,}["\']', "Generic Access Token", False),
    ]
    
    # Patterns to exclude (false positives)
    EXCLUDE_PATTERNS = [
        r'example',
        r'placeholder',
        r'your[_-]?api[_-]?key',
        r'xxx+',
        r'test[_-]?key',
        r'dummy',
        r'fake',
        r'sample',
        r'\.\.\.',
        r'<[^>]+>',  # Template placeholders like <API_KEY>
        r'\$\{[^}]+\}',  # Variable interpolation
        r'os\.environ',
        r'process\.env',
        r'getenv',
        r'ENV\[',
    ]
    
    def scan(self, content: str, filepath: str) -> List[Finding]:
        findings = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            # Skip if line contains exclusion patterns
            if any(re.search(p, line, re.IGNORECASE) for p in self.EXCLUDE_PATTERNS):
                continue
            
            # Skip comments
            stripped = line.strip()
            if stripped.startswith(('#', '//', '/*', '*', '"""', "'''")):
                continue
            
            for pattern, secret_type, high_confidence in self.SECRET_PATTERNS:
                match = re.search(pattern, line)
                if match:
                    # Additional validation for high confidence patterns
                    if high_confidence or self._validate_secret_context(line, match.group()):
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            rule_name=self.name,
                            severity=Severity.CRITICAL if high_confidence else Severity.HIGH,
                            filepath=filepath,
                            line_number=line_num,
                            code_snippet=self._mask_secret(line, match),
                            message=f"{secret_type} detected in source code",
                            fix_suggestion=(
                                f"Remove the hardcoded {secret_type.lower()} and use environment variables:\n"
                                f"  Python: os.environ.get('{self._get_env_var_name(secret_type)}')\n"
                                f"  Node.js: process.env.{self._get_env_var_name(secret_type)}"
                            ),
                        ))
        
        return findings
    
    def _validate_secret_context(self, line: str, secret: str) -> bool:
        """Additional validation to reduce false positives."""
        # Check if it looks like an assignment
        assignment_patterns = [
            r'=\s*["\']',
            r':\s*["\']',
            r'api_key\s*=',
            r'secret\s*=',
            r'token\s*=',
        ]
        return any(re.search(p, line, re.IGNORECASE) for p in assignment_patterns)
    
    def _mask_secret(self, line: str, match: re.Match) -> str:
        """Mask the secret in output for safety."""
        secret = match.group()
        if len(secret) > 8:
            masked = secret[:4] + '*' * (len(secret) - 8) + secret[-4:]
        else:
            masked = '*' * len(secret)
        return line.replace(secret, masked)
    
    def _get_env_var_name(self, secret_type: str) -> str:
        """Generate appropriate environment variable name."""
        type_to_env = {
            "OpenAI API Key": "OPENAI_API_KEY",
            "OpenAI Project API Key": "OPENAI_API_KEY",
            "Anthropic API Key": "ANTHROPIC_API_KEY",
            "AWS Access Key ID": "AWS_ACCESS_KEY_ID",
            "AWS Secret Key": "AWS_SECRET_ACCESS_KEY",
            "Google API Key": "GOOGLE_API_KEY",
            "GitHub Personal Access Token": "GITHUB_TOKEN",
            "Stripe Live Secret Key": "STRIPE_SECRET_KEY",
            "Stripe Test Secret Key": "STRIPE_TEST_SECRET_KEY",
        }
        return type_to_env.get(secret_type, "API_KEY")


class HardcodedPasswordPattern(BasePattern):
    """Detect hardcoded passwords in source code."""
    
    rule_id = "SEC002"
    name = "Hardcoded Password"
    description = "Password hardcoded in source code."
    severity = Severity.CRITICAL
    
    PASSWORD_PATTERNS = [
        (r'password\s*=\s*["\'][^"\']{4,}["\']', "Password assignment"),
        (r'passwd\s*=\s*["\'][^"\']{4,}["\']', "Password assignment"),
        (r'pwd\s*=\s*["\'][^"\']{4,}["\']', "Password assignment"),
        (r'["\']password["\']\s*:\s*["\'][^"\']{4,}["\']', "Password in dict/object"),
        (r'DB_PASSWORD\s*=\s*["\'][^"\']+["\']', "Database password"),
        (r'MYSQL_PASSWORD\s*=\s*["\'][^"\']+["\']', "MySQL password"),
        (r'POSTGRES_PASSWORD\s*=\s*["\'][^"\']+["\']', "PostgreSQL password"),
    ]
    
    EXCLUDE_PATTERNS = [
        r'password\s*=\s*["\'][\s]*["\']',  # Empty password
        r'password\s*=\s*None',
        r'password\s*=\s*null',
        r'os\.environ',
        r'process\.env',
        r'getenv',
        r'input\s*\(',
        r'getpass',
        r'<password>',
        r'\$\{',
        r'your[_-]?password',
        r'example',
        r'placeholder',
    ]
    
    def scan(self, content: str, filepath: str) -> List[Finding]:
        findings = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            # Skip excluded patterns
            if any(re.search(p, line, re.IGNORECASE) for p in self.EXCLUDE_PATTERNS):
                continue
            
            for pattern, desc in self.PASSWORD_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(self._create_finding(
                        filepath=filepath,
                        line_number=line_num,
                        code_snippet=self._mask_password(line),
                        message=f"{desc} - never hardcode passwords",
                        fix_suggestion=(
                            "Use environment variables or a secrets manager:\n"
                            "  Python: os.environ.get('DB_PASSWORD')\n"
                            "  Or use: getpass.getpass() for interactive input"
                        ),
                    ))
                    break
        
        return findings
    
    def _mask_password(self, line: str) -> str:
        """Mask password values in output."""
        # Replace quoted strings after password= with asterisks
        return re.sub(
            r'(password\s*=\s*["\'])[^"\']+(["\'])',
            r'\1********\2',
            line,
            flags=re.IGNORECASE
        )


class HardcodedConnectionStringPattern(BasePattern):
    """Detect hardcoded database connection strings."""
    
    rule_id = "SEC003"
    name = "Hardcoded Connection String"
    description = "Database connection string with credentials hardcoded in source code."
    severity = Severity.CRITICAL
    
    CONN_STRING_PATTERNS = [
        # PostgreSQL
        (r'postgresql://[^:]+:[^@]+@[^/]+', "PostgreSQL connection string with credentials"),
        (r'postgres://[^:]+:[^@]+@[^/]+', "PostgreSQL connection string with credentials"),
        
        # MySQL
        (r'mysql://[^:]+:[^@]+@[^/]+', "MySQL connection string with credentials"),
        (r'mysql\+pymysql://[^:]+:[^@]+@[^/]+', "MySQL connection string with credentials"),
        
        # MongoDB
        (r'mongodb://[^:]+:[^@]+@[^/]+', "MongoDB connection string with credentials"),
        (r'mongodb\+srv://[^:]+:[^@]+@[^/]+', "MongoDB Atlas connection string"),
        
        # Redis
        (r'redis://:[^@]+@[^/]+', "Redis connection string with password"),
        
        # MSSQL
        (r'mssql://[^:]+:[^@]+@[^/]+', "MSSQL connection string with credentials"),
    ]
    
    def scan(self, content: str, filepath: str) -> List[Finding]:
        findings = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            # Skip if it's using environment variables
            if 'os.environ' in line or 'process.env' in line or 'getenv' in line:
                continue
            
            for pattern, desc in self.CONN_STRING_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(self._create_finding(
                        filepath=filepath,
                        line_number=line_num,
                        code_snippet=self._mask_connection_string(line),
                        message=desc,
                        fix_suggestion=(
                            "Store connection strings in environment variables:\n"
                            "  DATABASE_URL=postgresql://user:pass@host/db\n"
                            "  Then: os.environ.get('DATABASE_URL')"
                        ),
                    ))
                    break
        
        return findings
    
    def _mask_connection_string(self, line: str) -> str:
        """Mask credentials in connection string."""
        # Replace password portion with asterisks
        return re.sub(
            r'(://[^:]+:)[^@]+(@)',
            r'\1********\2',
            line
        )


# Export all patterns
SECRETS_PATTERNS = [
    HardcodedSecretsPattern,
    HardcodedPasswordPattern,
    HardcodedConnectionStringPattern,
]
