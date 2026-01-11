"""Tests for AI Code Guard scanner."""

import pytest
from pathlib import Path

from ai_code_guard import Scanner, ScanConfig, Severity


class TestScanner:
    """Test the main scanner functionality."""
    
    def test_detects_hardcoded_openai_key(self):
        """Should detect OpenAI API keys."""
        scanner = Scanner()
        code = '''api_key = "sk-proj-abc123def456ghi789jkl012mno345pqr678"'''
        
        # Create temp file
        temp_file = Path("/tmp/test_secrets.py")
        temp_file.write_text(code)
        
        findings = scanner.scan_file(temp_file)
        
        assert len(findings) >= 1
        assert any(f.rule_id == "SEC001" for f in findings)
        
        temp_file.unlink()
    
    def test_detects_sql_injection(self):
        """Should detect SQL injection via f-string."""
        scanner = Scanner()
        code = '''
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return query
'''
        temp_file = Path("/tmp/test_sqli.py")
        temp_file.write_text(code)
        
        findings = scanner.scan_file(temp_file)
        
        assert len(findings) >= 1
        assert any(f.rule_id == "INJ001" for f in findings)
        
        temp_file.unlink()
    
    def test_detects_prompt_injection(self):
        """Should detect prompt injection patterns."""
        scanner = Scanner()
        code = '''
def chat(user_input):
    prompt = f"You are a helper. User says: {user_input}"
    return prompt
'''
        temp_file = Path("/tmp/test_prompt.py")
        temp_file.write_text(code)
        
        findings = scanner.scan_file(temp_file)
        
        assert len(findings) >= 1
        assert any(f.rule_id == "PRI001" for f in findings)
        
        temp_file.unlink()
    
    def test_detects_command_injection(self):
        """Should detect command injection via os.system."""
        scanner = Scanner()
        code = '''
import os
def run(cmd):
    os.system(f"echo {cmd}")
'''
        temp_file = Path("/tmp/test_cmdi.py")
        temp_file.write_text(code)
        
        findings = scanner.scan_file(temp_file)
        
        assert len(findings) >= 1
        assert any(f.rule_id == "INJ002" for f in findings)
        
        temp_file.unlink()
    
    def test_ignores_safe_patterns(self):
        """Should not flag parameterized queries."""
        scanner = Scanner()
        code = '''
def get_user(user_id):
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
'''
        temp_file = Path("/tmp/test_safe.py")
        temp_file.write_text(code)
        
        findings = scanner.scan_file(temp_file)
        sql_findings = [f for f in findings if f.rule_id == "INJ001"]
        
        assert len(sql_findings) == 0
        
        temp_file.unlink()
    
    def test_ignores_env_var_usage(self):
        """Should not flag secrets loaded from environment."""
        scanner = Scanner()
        code = '''
import os
api_key = os.environ.get("OPENAI_API_KEY")
'''
        temp_file = Path("/tmp/test_env.py")
        temp_file.write_text(code)
        
        findings = scanner.scan_file(temp_file)
        secret_findings = [f for f in findings if f.rule_id == "SEC001"]
        
        assert len(secret_findings) == 0
        
        temp_file.unlink()
    
    def test_severity_filtering(self):
        """Should filter by minimum severity."""
        config = ScanConfig(min_severity=Severity.HIGH)
        scanner = Scanner(config=config)
        
        code = '''
# This would normally trigger a LOW severity finding
import requests
requests.get("https://webhook.site/test")
'''
        temp_file = Path("/tmp/test_severity.py")
        temp_file.write_text(code)
        
        findings = scanner.scan_file(temp_file)
        
        # Should not include LOW severity findings
        assert all(f.severity.priority >= Severity.HIGH.priority for f in findings)
        
        temp_file.unlink()


class TestPatterns:
    """Test individual pattern detection."""
    
    def test_github_token_detection(self):
        """Should detect GitHub personal access tokens."""
        scanner = Scanner()
        code = '''token = "ghp_abc123def456ghi789jkl012mno345pqrs"'''
        
        temp_file = Path("/tmp/test_gh.py")
        temp_file.write_text(code)
        
        findings = scanner.scan_file(temp_file)
        
        assert any("GitHub" in f.message for f in findings)
        
        temp_file.unlink()
    
    def test_connection_string_detection(self):
        """Should detect database connection strings."""
        scanner = Scanner()
        code = '''db = "mongodb://user:pass123@localhost:27017/mydb"'''
        
        temp_file = Path("/tmp/test_conn.py")
        temp_file.write_text(code)
        
        findings = scanner.scan_file(temp_file)
        
        assert any(f.rule_id == "SEC003" for f in findings)
        
        temp_file.unlink()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
