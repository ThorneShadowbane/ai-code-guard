"""Injection vulnerability detection patterns.

AI coding assistants frequently generate code with injection vulnerabilities,
particularly SQL injection via string formatting - a pattern that was common
in older training data.
"""

import re
from typing import List

from .base import BasePattern, Finding, Severity


class SQLInjectionPattern(BasePattern):
    """Detect SQL injection vulnerabilities from string formatting."""
    
    rule_id = "INJ001"
    name = "SQL Injection"
    description = (
        "SQL query constructed using string formatting or concatenation. "
        "This is a common pattern in AI-generated code due to older training data."
    )
    severity = Severity.CRITICAL
    
    # Patterns that indicate SQL with string formatting
    SQL_PATTERNS = [
        # f-string SQL
        (r'(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\s+.*\{[^}]+\}', 
         "SQL query uses f-string interpolation"),
        
        # .format() SQL
        (r'(SELECT|INSERT|UPDATE|DELETE).*\.format\s*\(',
         "SQL query uses .format()"),
        
        # % formatting SQL
        (r'(SELECT|INSERT|UPDATE|DELETE).*%\s*\(',
         "SQL query uses % string formatting"),
        
        # String concatenation SQL
        (r'(SELECT|INSERT|UPDATE|DELETE).*\+\s*(user|input|param|query|request)',
         "SQL query uses string concatenation with user input"),
        
        # execute with f-string
        (r'\.execute\s*\(\s*f["\']',
         "Database execute() with f-string"),
        
        # Raw query construction
        (r'query\s*=\s*f["\'].*(SELECT|INSERT|UPDATE|DELETE)',
         "Query variable constructed with f-string"),
    ]
    
    # Safe patterns to exclude
    SAFE_PATTERNS = [
        r'execute\s*\([^,]+,\s*\(',   # Parameterized query with tuple
        r'execute\s*\([^,]+,\s*\[',   # Parameterized query with list
        r'execute\s*\([^,]+,\s*\{',   # Parameterized query with dict
        r'%s',                         # Placeholder (when used correctly)
        r'\?',                         # SQLite placeholder
        r':\w+',                       # Named parameter
    ]
    
    def scan(self, content: str, filepath: str) -> List[Finding]:
        findings = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            # Skip if line has safe parameterized patterns
            if any(re.search(p, line) for p in self.SAFE_PATTERNS):
                continue
            
            for pattern, message in self.SQL_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(self._create_finding(
                        filepath=filepath,
                        line_number=line_num,
                        code_snippet=line,
                        message=message,
                        fix_suggestion=(
                            "Use parameterized queries instead:\n"
                            "  cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))\n"
                            "  cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))\n"
                            "  cursor.execute('SELECT * FROM users WHERE id = :id', {'id': user_id})"
                        ),
                    ))
                    break
        
        return findings


class CommandInjectionPattern(BasePattern):
    """Detect command injection vulnerabilities."""
    
    rule_id = "INJ002"
    name = "Command Injection"
    description = (
        "Shell command constructed with user input. "
        "Attackers can execute arbitrary system commands."
    )
    severity = Severity.CRITICAL
    
    DANGEROUS_PATTERNS = [
        # os.system with formatting
        (r'os\.system\s*\(\s*f["\']', "os.system() with f-string"),
        (r'os\.system\s*\([^)]*\+', "os.system() with string concatenation"),
        (r'os\.system\s*\([^)]*\.format', "os.system() with .format()"),
        (r'os\.system\s*\([^)]*%', "os.system() with % formatting"),
        
        # subprocess with shell=True
        (r'subprocess\.(run|call|Popen)\s*\([^)]*shell\s*=\s*True', 
         "subprocess with shell=True"),
        
        # subprocess with string command
        (r'subprocess\.(run|call|Popen)\s*\(\s*f["\']',
         "subprocess with f-string command"),
        
        # os.popen
        (r'os\.popen\s*\(\s*f["\']', "os.popen() with f-string"),
        (r'os\.popen\s*\([^)]*\+', "os.popen() with string concatenation"),
        
        # eval/exec (related but different vulnerability)
        (r'eval\s*\(\s*(user|input|request|query)', "eval() with user input"),
        (r'exec\s*\(\s*(user|input|request|query)', "exec() with user input"),
        
        # Node.js child_process
        (r'child_process\.exec\s*\(\s*`', "child_process.exec with template literal"),
        (r'child_process\.exec\s*\([^)]*\+', "child_process.exec with concatenation"),
    ]
    
    def scan(self, content: str, filepath: str) -> List[Finding]:
        findings = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            for pattern, message in self.DANGEROUS_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(self._create_finding(
                        filepath=filepath,
                        line_number=line_num,
                        code_snippet=line,
                        message=message,
                        fix_suggestion=(
                            "Use subprocess with a list of arguments (no shell):\n"
                            "  subprocess.run(['ls', '-la', directory], check=True)\n"
                            "  # NOT: subprocess.run(f'ls -la {directory}', shell=True)\n\n"
                            "If shell features are needed, use shlex.quote():\n"
                            "  import shlex\n"
                            "  subprocess.run(f'command {shlex.quote(user_input)}', shell=True)"
                        ),
                    ))
                    break
        
        return findings


class PathTraversalPattern(BasePattern):
    """Detect path traversal vulnerabilities."""
    
    rule_id = "INJ003"
    name = "Path Traversal"
    description = (
        "File path constructed with user input without validation. "
        "Attackers can access files outside intended directories."
    )
    severity = Severity.HIGH
    
    PATH_PATTERNS = [
        # Direct path construction
        (r'open\s*\(\s*f["\'].*\{.*(?:user|input|filename|path|name).*\}',
         "File open with f-string containing user input"),
        
        (r'open\s*\([^)]*\+\s*(?:user|input|filename)',
         "File open with concatenated user input"),
        
        # Path operations
        (r'os\.path\.join\s*\([^)]*(?:user|input|request)',
         "os.path.join with user input - verify no '..' allowed"),
        
        (r'Path\s*\(\s*f["\'].*\{',
         "pathlib.Path with f-string interpolation"),
        
        # File read/write operations
        (r'(read|write)_file\s*\(\s*f["\'].*\{',
         "File operation with f-string path"),
        
        # Send file (web frameworks)
        (r'send_file\s*\(\s*f["\'].*\{',
         "send_file with f-string - potential path traversal"),
        
        (r'send_from_directory\s*\([^,]+,\s*(?:user|input|request|filename)',
         "send_from_directory with user-controlled filename"),
    ]
    
    def scan(self, content: str, filepath: str) -> List[Finding]:
        findings = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            for pattern, message in self.PATH_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    # Check if there's validation nearby
                    context_start = max(0, line_num - 5)
                    context = '\n'.join(lines[context_start:line_num])
                    
                    has_validation = any(p in context.lower() for p in [
                        'secure_filename',
                        'os.path.basename',
                        'path.name',
                        '.resolve()',
                        'is_relative_to',
                        'startswith',
                        '../' in context and 'if' in context,
                    ])
                    
                    if not has_validation:
                        findings.append(self._create_finding(
                            filepath=filepath,
                            line_number=line_num,
                            code_snippet=line,
                            message=message,
                            fix_suggestion=(
                                "Validate and sanitize file paths:\n"
                                "  from werkzeug.utils import secure_filename\n"
                                "  safe_name = secure_filename(user_filename)\n\n"
                                "  # Or use pathlib to verify path is within allowed directory:\n"
                                "  base = Path('/safe/directory').resolve()\n"
                                "  target = (base / user_path).resolve()\n"
                                "  if not target.is_relative_to(base):\n"
                                "      raise ValueError('Path traversal detected')"
                            ),
                        ))
                        break
        
        return findings


class XSSPattern(BasePattern):
    """Detect potential Cross-Site Scripting vulnerabilities."""
    
    rule_id = "INJ004"
    name = "Cross-Site Scripting (XSS)"
    description = (
        "User input rendered in HTML without proper escaping. "
        "Common in AI-generated web code."
    )
    severity = Severity.HIGH
    
    file_extensions = [".py", ".js", ".ts", ".jsx", ".tsx", ".html", ".vue", ".php"]
    
    XSS_PATTERNS = [
        # Jinja2 without escaping
        (r'\{\{\s*[^}|]*\s*\}\}', "Jinja2 template - verify autoescape is enabled"),
        
        # Django mark_safe
        (r'mark_safe\s*\([^)]*(?:user|input|request)', 
         "mark_safe() with user input bypasses XSS protection"),
        
        # innerHTML
        (r'\.innerHTML\s*=\s*(?:user|input|data|response)',
         "innerHTML set to user-controlled data"),
        
        # React dangerouslySetInnerHTML
        (r'dangerouslySetInnerHTML\s*=\s*\{',
         "dangerouslySetInnerHTML - ensure content is sanitized"),
        
        # document.write
        (r'document\.write\s*\([^)]*(?:user|input|data)',
         "document.write with user input"),
        
        # jQuery html()
        (r'\$\([^)]+\)\.html\s*\([^)]*(?:user|input|data|response)',
         "jQuery .html() with user-controlled data"),
        
        # v-html in Vue
        (r'v-html\s*=\s*["\'][^"\']*(?:user|input)',
         "Vue v-html with user input"),
    ]
    
    def scan(self, content: str, filepath: str) -> List[Finding]:
        findings = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            for pattern, message in self.XSS_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(self._create_finding(
                        filepath=filepath,
                        line_number=line_num,
                        code_snippet=line,
                        message=message,
                        fix_suggestion=(
                            "Escape user input before rendering:\n"
                            "  Python: from markupsafe import escape; escape(user_input)\n"
                            "  JavaScript: Use textContent instead of innerHTML\n"
                            "  React: Avoid dangerouslySetInnerHTML, use DOMPurify if needed\n"
                            "  Vue: Use {{ }} interpolation instead of v-html"
                        ),
                    ))
                    break
        
        return findings


# Export all patterns
INJECTION_PATTERNS = [
    SQLInjectionPattern,
    CommandInjectionPattern,
    PathTraversalPattern,
    XSSPattern,
]
