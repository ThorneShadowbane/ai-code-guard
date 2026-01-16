"""Tests for AI Code Guard Pro."""

import pytest
from pathlib import Path
import tempfile

from ai_code_guard import Scanner, Config, Severity, scan
from ai_code_guard.analyzers.secrets import SecretsAnalyzer, calculate_shannon_entropy
from ai_code_guard.analyzers.python_ast import PythonASTAnalyzer
from ai_code_guard.analyzers.prompt_injection import PromptInjectionAnalyzer


class TestSecretsAnalyzer:
    """Test secret detection."""
    
    def test_detect_openai_key(self):
        """Should detect OpenAI API keys."""
        code = 'api_key = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnop"'
        analyzer = SecretsAnalyzer(Path("test.py"), code, Config())
        findings = analyzer.analyze()
        
        assert len(findings) >= 1
        assert any("OpenAI" in f.title for f in findings)
    
    def test_detect_aws_key(self):
        """Should detect AWS access keys."""
        code = 'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"'
        analyzer = SecretsAnalyzer(Path("test.py"), code, Config())
        findings = analyzer.analyze()
        
        assert len(findings) >= 1
        assert any("AWS" in f.title for f in findings)
    
    def test_detect_github_token(self):
        """Should detect GitHub tokens."""
        code = 'token = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"'
        analyzer = SecretsAnalyzer(Path("test.py"), code, Config())
        findings = analyzer.analyze()
        
        assert len(findings) >= 1
        assert any("GitHub" in f.title for f in findings)
    
    def test_ignore_env_var_reference(self):
        """Should not flag environment variable references."""
        code = 'api_key = os.environ.get("OPENAI_API_KEY")'
        analyzer = SecretsAnalyzer(Path("test.py"), code, Config())
        findings = analyzer.analyze()
        
        # Should not detect this as a hardcoded secret
        assert not any("Hardcoded" in f.title or "API Key" in f.title for f in findings)
    
    def test_ignore_placeholder(self):
        """Should ignore obvious placeholders."""
        code = 'password = "changeme"'
        analyzer = SecretsAnalyzer(Path("test.py"), code, Config())
        findings = analyzer.analyze()
        
        # Should not flag placeholder values
        assert not any(f.severity == Severity.CRITICAL for f in findings)


class TestShannonEntropy:
    """Test entropy calculation."""
    
    def test_low_entropy(self):
        """Low entropy for repeated characters."""
        assert calculate_shannon_entropy("aaaaaaaaaa") < 1.0
    
    def test_high_entropy(self):
        """High entropy for random-looking strings."""
        assert calculate_shannon_entropy("aB3$xY9@kL") > 3.0
    
    def test_empty_string(self):
        """Empty string should have zero entropy."""
        assert calculate_shannon_entropy("") == 0.0


class TestPythonASTAnalyzer:
    """Test AST-based Python analysis."""
    
    def test_detect_sql_injection_fstring(self):
        """Should detect SQL injection via f-string."""
        code = '''
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
'''
        analyzer = PythonASTAnalyzer(Path("test.py"), code, Config())
        findings = analyzer.analyze()
        
        assert len(findings) >= 1
        assert any("SQL" in f.title for f in findings)
    
    def test_detect_sql_injection_format(self):
        """Should detect SQL injection via .format()."""
        code = '''
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = {}".format(user_id)
    cursor.execute(query)
'''
        analyzer = PythonASTAnalyzer(Path("test.py"), code, Config())
        findings = analyzer.analyze()
        
        assert len(findings) >= 1
        assert any("SQL" in f.title for f in findings)
    
    def test_detect_command_injection(self):
        """Should detect command injection via os.system."""
        code = '''
import os
def run_command(user_input):
    os.system(f"echo {user_input}")
'''
        analyzer = PythonASTAnalyzer(Path("test.py"), code, Config())
        findings = analyzer.analyze()
        
        assert len(findings) >= 1
        assert any("Command" in f.title for f in findings)
    
    def test_detect_unsafe_yaml(self):
        """Should detect unsafe yaml.load."""
        code = '''
import yaml
data = yaml.load(user_input)
'''
        analyzer = PythonASTAnalyzer(Path("test.py"), code, Config())
        findings = analyzer.analyze()
        
        assert len(findings) >= 1
        assert any("YAML" in f.title for f in findings)
    
    def test_safe_yaml_no_alert(self):
        """Should not alert on yaml.safe_load."""
        code = '''
import yaml
data = yaml.safe_load(user_input)
'''
        analyzer = PythonASTAnalyzer(Path("test.py"), code, Config())
        findings = analyzer.analyze()
        
        assert not any("YAML" in f.title for f in findings)
    
    def test_detect_pickle_loads(self):
        """Should detect unsafe pickle.loads."""
        code = '''
import pickle
data = pickle.loads(user_data)
'''
        analyzer = PythonASTAnalyzer(Path("test.py"), code, Config())
        findings = analyzer.analyze()
        
        assert len(findings) >= 1
        assert any("Pickle" in f.title or "Deserialization" in f.title for f in findings)
    
    def test_detect_eval(self):
        """Should detect dangerous eval usage."""
        code = '''
result = eval(user_expression)
'''
        analyzer = PythonASTAnalyzer(Path("test.py"), code, Config())
        findings = analyzer.analyze()
        
        assert len(findings) >= 1
        assert any("eval" in f.title.lower() for f in findings)


class TestPromptInjectionAnalyzer:
    """Test prompt injection detection."""
    
    def test_detect_direct_injection_fstring(self):
        """Should detect prompt injection via f-string."""
        code = '''
import openai
def chat(user_input):
    prompt = f"You are a helper. User says: {user_input}"
    response = openai.ChatCompletion.create(messages=[{"role": "user", "content": prompt}])
'''
        analyzer = PromptInjectionAnalyzer(Path("test.py"), code, Config())
        findings = analyzer.analyze()
        
        assert len(findings) >= 1
        assert any("Prompt" in f.title for f in findings)
    
    def test_detect_system_prompt_injection(self):
        """Should detect user data in system prompt."""
        code = '''
messages = [
    {"role": "system", "content": f"Help user: {user_data}"},
    {"role": "user", "content": query}
]
'''
        analyzer = PromptInjectionAnalyzer(Path("test.py"), code, Config())
        findings = analyzer.analyze()
        
        # Should flag user data in system prompt
        assert len(findings) >= 1


class TestScanner:
    """Test the main scanner."""
    
    def test_scan_directory(self):
        """Should scan a directory recursively."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create test file
            test_file = Path(tmpdir) / "test.py"
            test_file.write_text('api_key = "sk-proj-' + 'x' * 80 + '"')
            
            result = scan(tmpdir)
            
            assert result.files_scanned >= 1
            assert len(result.findings) >= 1
    
    def test_scan_single_file(self):
        """Should scan a single file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write('password = "supersecret123456"')
            f.flush()
            
            result = scan(f.name)
            
            assert result.files_scanned == 1
    
    def test_ignore_patterns(self):
        """Should respect ignore patterns."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create test files
            test_file = Path(tmpdir) / "test_secret.py"
            test_file.write_text('api_key = "sk-proj-' + 'x' * 80 + '"')
            
            config = Config(ignore_patterns=["test_*.py"])
            scanner = Scanner(config)
            result = scanner.scan_path(Path(tmpdir))
            
            # Should not scan the test file
            assert result.files_scanned == 0
    
    def test_severity_filtering(self):
        """Should filter by minimum severity."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write('api_key = "sk-proj-' + 'x' * 80 + '"')  # CRITICAL
            f.flush()
            
            # Only show CRITICAL issues
            config = Config(min_severity=Severity.CRITICAL)
            result = scan(f.name, config=config)
            
            assert all(f.severity == Severity.CRITICAL for f in result.findings)


class TestSARIFOutput:
    """Test SARIF output format."""
    
    def test_sarif_structure(self):
        """Should produce valid SARIF structure."""
        from ai_code_guard.reporters import SARIFReporter
        from ai_code_guard.models import Finding, Location, ScanResult
        
        result = ScanResult(
            findings=[
                Finding(
                    rule_id="SEC001",
                    title="Test Finding",
                    description="Test description",
                    severity=Severity.HIGH,
                    category=Category.SECRETS,
                    location=Location(filepath=Path("test.py"), line=1),
                )
            ],
            files_scanned=1,
        )
        
        reporter = SARIFReporter()
        output = reporter.report(result)
        
        import json
        sarif = json.loads(output)
        
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1
        assert len(sarif["runs"][0]["results"]) == 1


# Import Category for test
from ai_code_guard.models import Category


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
