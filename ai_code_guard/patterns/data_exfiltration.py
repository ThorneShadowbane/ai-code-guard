"""Data exfiltration risk detection patterns.

These patterns detect code that might exfiltrate sensitive data,
including suspicious outbound requests and encoding patterns that
could be used to hide data theft.
"""

import re
from typing import List

from .base import BasePattern, Finding, Severity


class SuspiciousOutboundRequestPattern(BasePattern):
    """Detect suspicious outbound HTTP requests with sensitive data."""
    
    rule_id = "EXF001"
    name = "Suspicious Outbound Request"
    description = (
        "HTTP request that may be sending sensitive data to external endpoints. "
        "This could indicate data exfiltration or accidental data leakage."
    )
    severity = Severity.MEDIUM
    
    # Sensitive variable names that shouldn't be sent externally
    SENSITIVE_VARS = [
        'password', 'passwd', 'pwd', 'secret', 'token', 'api_key', 'apikey',
        'private_key', 'privatekey', 'credentials', 'auth', 'session',
        'credit_card', 'creditcard', 'ssn', 'social_security',
        'bank_account', 'routing_number', 'pin',
    ]
    
    REQUEST_PATTERNS = [
        # Python requests
        r'requests\.(get|post|put|patch|delete)\s*\(',
        # Python urllib
        r'urllib\.request\.urlopen',
        # Python httpx
        r'httpx\.(get|post|put|patch|delete|AsyncClient)',
        # Python aiohttp
        r'aiohttp\.ClientSession',
        # JavaScript fetch
        r'fetch\s*\(',
        # JavaScript axios
        r'axios\.(get|post|put|patch|delete)',
        # Node http
        r'http\.request',
        r'https\.request',
    ]
    
    def scan(self, content: str, filepath: str) -> List[Finding]:
        findings = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            # Check if line has an HTTP request
            has_request = any(re.search(p, line, re.IGNORECASE) for p in self.REQUEST_PATTERNS)
            if not has_request:
                continue
            
            # Check if sensitive variables are included
            line_lower = line.lower()
            for sensitive_var in self.SENSITIVE_VARS:
                if sensitive_var in line_lower:
                    findings.append(self._create_finding(
                        filepath=filepath,
                        line_number=line_num,
                        code_snippet=line,
                        message=f"HTTP request includes sensitive variable: '{sensitive_var}'",
                        fix_suggestion=(
                            "Review if sensitive data should be sent externally:\n"
                            "  1. Is this request to a trusted endpoint?\n"
                            "  2. Is the connection secure (HTTPS)?\n"
                            "  3. Is this data actually needed for the request?\n"
                            "  4. Consider logging/auditing sensitive data transmissions"
                        ),
                    ))
                    break
        
        return findings


class Base64EncodingSuspiciousPattern(BasePattern):
    """Detect suspicious base64 encoding of sensitive data."""
    
    rule_id = "EXF002"
    name = "Suspicious Data Encoding"
    description = (
        "Sensitive data being base64 encoded before transmission. "
        "Base64 encoding is sometimes used to obfuscate data exfiltration."
    )
    severity = Severity.LOW
    
    ENCODING_PATTERNS = [
        (r'base64\.(b64encode|encode)\s*\([^)]*(?:password|secret|token|key|credential)',
         "Base64 encoding sensitive data"),
        (r'btoa\s*\([^)]*(?:password|secret|token|key)',
         "JavaScript btoa() on sensitive data"),
        (r'Buffer\.from\s*\([^)]*(?:password|secret|token)',
         "Node.js Buffer encoding sensitive data"),
    ]
    
    def scan(self, content: str, filepath: str) -> List[Finding]:
        findings = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            for pattern, message in self.ENCODING_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(self._create_finding(
                        filepath=filepath,
                        line_number=line_num,
                        code_snippet=line,
                        message=message,
                        fix_suggestion=(
                            "Review the purpose of encoding sensitive data:\n"
                            "  - For storage: Use proper encryption (e.g., bcrypt for passwords)\n"
                            "  - For transmission: Ensure secure channel (HTTPS/TLS)\n"
                            "  - Base64 is NOT encryption - data can be easily decoded"
                        ),
                    ))
                    break
        
        return findings


class HardcodedExternalURLPattern(BasePattern):
    """Detect hardcoded external URLs that could be data exfiltration endpoints."""
    
    rule_id = "EXF003"
    name = "Hardcoded External URL"
    description = (
        "Hardcoded URL to external service. Review if this is intended and secure."
    )
    severity = Severity.LOW
    
    # Suspicious domains/patterns
    SUSPICIOUS_DOMAINS = [
        r'ngrok\.io',
        r'webhook\.site',
        r'requestbin\.com',
        r'pipedream\.net',
        r'burpcollaborator\.net',
        r'oastify\.com',
        r'interact\.sh',
        r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+',  # Raw IP addresses
    ]
    
    def scan(self, content: str, filepath: str) -> List[Finding]:
        findings = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            for domain in self.SUSPICIOUS_DOMAINS:
                if re.search(domain, line, re.IGNORECASE):
                    findings.append(self._create_finding(
                        filepath=filepath,
                        line_number=line_num,
                        code_snippet=line,
                        message=f"Potentially suspicious external URL pattern detected",
                        fix_suggestion=(
                            "Review this external URL:\n"
                            "  - Is this a testing/debugging tool left in production code?\n"
                            "  - Are you sending data to a trusted endpoint?\n"
                            "  - Consider using environment variables for external URLs\n"
                            "  - Remove debugging tools like ngrok/webhook.site before deployment"
                        ),
                    ))
                    break
        
        return findings


class EnvironmentVariableLeakPattern(BasePattern):
    """Detect patterns that might leak environment variables."""
    
    rule_id = "EXF004"
    name = "Environment Variable Exposure Risk"
    description = (
        "Pattern that might expose environment variables containing secrets."
    )
    severity = Severity.MEDIUM
    
    LEAK_PATTERNS = [
        # Logging all env vars
        (r'print\s*\(\s*os\.environ\s*\)', "Printing all environment variables"),
        (r'console\.log\s*\(\s*process\.env\s*\)', "Logging all environment variables"),
        (r'logger\.\w+\s*\(\s*os\.environ', "Logging environment variables"),
        
        # Serializing env vars
        (r'json\.dumps\s*\(\s*dict\s*\(\s*os\.environ', "Serializing all environment variables"),
        (r'JSON\.stringify\s*\(\s*process\.env', "Stringifying all environment variables"),
        
        # Returning env vars in API
        (r'return\s+.*os\.environ', "Returning environment variables from function"),
        (r'response\s*=.*os\.environ', "Including environment variables in response"),
    ]
    
    def scan(self, content: str, filepath: str) -> List[Finding]:
        findings = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            for pattern, message in self.LEAK_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(self._create_finding(
                        filepath=filepath,
                        line_number=line_num,
                        code_snippet=line,
                        message=message,
                        fix_suggestion=(
                            "Avoid exposing all environment variables:\n"
                            "  - Log specific, non-sensitive variables only\n"
                            "  - Never return env vars in API responses\n"
                            "  - Filter out sensitive keys before any logging/serialization"
                        ),
                    ))
                    break
        
        return findings


# Export all patterns
DATA_EXFILTRATION_PATTERNS = [
    SuspiciousOutboundRequestPattern,
    Base64EncodingSuspiciousPattern,
    HardcodedExternalURLPattern,
    EnvironmentVariableLeakPattern,
]
