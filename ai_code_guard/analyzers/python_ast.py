"""Python AST-based security analyzer with taint tracking."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..models import Category, Config, Finding, Location, Severity


@dataclass
class TaintedVariable:
    """Tracks a variable that contains user-controlled data."""
    
    name: str
    source: str  # Where the taint originated
    line: int
    propagated_from: str | None = None


@dataclass
class TaintContext:
    """Tracks tainted variables through the AST."""
    
    tainted: dict[str, TaintedVariable] = field(default_factory=dict)
    
    # Known taint sources (user input)
    TAINT_SOURCES = {
        # Web frameworks
        "request.args", "request.form", "request.json", "request.data",
        "request.values", "request.headers", "request.cookies",
        "request.GET", "request.POST", "request.body",
        # Standard input
        "input", "sys.stdin", "raw_input",
        # File input
        "open", "read", "readline", "readlines",
        # Environment (partial taint)
        "os.environ", "os.getenv",
        # Command line
        "sys.argv", "argparse",
    }
    
    def is_tainted(self, name: str) -> bool:
        """Check if a variable is tainted."""
        return name in self.tainted
    
    def add_taint(self, name: str, source: str, line: int) -> None:
        """Mark a variable as tainted."""
        self.tainted[name] = TaintedVariable(name, source, line)
    
    def propagate_taint(self, from_name: str, to_name: str, line: int) -> None:
        """Propagate taint from one variable to another."""
        if from_name in self.tainted:
            original = self.tainted[from_name]
            self.tainted[to_name] = TaintedVariable(
                to_name, original.source, line, propagated_from=from_name
            )


class PythonASTAnalyzer(ast.NodeVisitor):
    """
    AST-based security analyzer for Python code.
    
    Improvements over regex-based scanning:
    - Understands code structure and scope
    - Tracks taint propagation through assignments
    - Handles complex expressions and function calls
    - Reduces false positives with context awareness
    """
    
    def __init__(self, filepath: Path, content: str, config: Config):
        self.filepath = filepath
        self.content = content
        self.lines = content.splitlines()
        self.config = config
        self.findings: list[Finding] = []
        self.taint_ctx = TaintContext()
        self.current_function: str | None = None
        self.in_class: str | None = None
        
    def analyze(self) -> list[Finding]:
        """Run all AST-based analyses."""
        try:
            tree = ast.parse(self.content, filename=str(self.filepath))
            self.visit(tree)
        except SyntaxError:
            # Fall back to regex-based scanning for invalid Python
            pass
        return self.findings
    
    def _get_code_snippet(self, lineno: int, context: int = 0) -> str:
        """Get code snippet around a line number."""
        start = max(0, lineno - 1 - context)
        end = min(len(self.lines), lineno + context)
        return "\n".join(self.lines[start:end])
    
    def _make_location(self, node: ast.AST) -> Location:
        """Create a Location from an AST node."""
        return Location(
            filepath=self.filepath,
            line=node.lineno,
            column=node.col_offset,
            end_line=getattr(node, 'end_lineno', None),
            end_column=getattr(node, 'end_col_offset', None),
        )
    
    def _get_full_attr_name(self, node: ast.AST) -> str | None:
        """Get the full dotted name of an attribute access."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            base = self._get_full_attr_name(node.value)
            if base:
                return f"{base}.{node.attr}"
        return None
    
    # === Taint Source Detection ===
    
    def visit_Assign(self, node: ast.Assign) -> None:
        """Track assignments for taint propagation."""
        # Check if RHS is a taint source
        source_name = self._check_taint_source(node.value)
        
        for target in node.targets:
            if isinstance(target, ast.Name):
                if source_name:
                    self.taint_ctx.add_taint(target.id, source_name, node.lineno)
                elif isinstance(node.value, ast.Name) and self.taint_ctx.is_tainted(node.value.id):
                    self.taint_ctx.propagate_taint(node.value.id, target.id, node.lineno)
        
        self.generic_visit(node)
    
    def _check_taint_source(self, node: ast.AST) -> str | None:
        """Check if a node represents a taint source."""
        full_name = self._get_full_attr_name(node)
        if full_name:
            for source in self.taint_ctx.TAINT_SOURCES:
                if full_name.startswith(source) or source in full_name:
                    return full_name
        
        # Check function calls
        if isinstance(node, ast.Call):
            func_name = self._get_full_attr_name(node.func)
            if func_name in {"input", "raw_input"}:
                return func_name
        
        return None
    
    # === SQL Injection Detection ===
    
    def visit_Call(self, node: ast.Call) -> None:
        """Detect dangerous function calls."""
        func_name = self._get_full_attr_name(node.func)
        
        # SQL Injection via execute()
        if func_name and func_name.endswith((".execute", ".executemany", ".raw")):
            self._check_sql_injection(node)
        
        # Command Injection
        if func_name in {"os.system", "os.popen", "subprocess.call", 
                         "subprocess.run", "subprocess.Popen"}:
            self._check_command_injection(node)
        
        # Dangerous deserialization
        if func_name in {"pickle.loads", "pickle.load", "yaml.load", 
                         "yaml.unsafe_load", "marshal.loads"}:
            self._check_unsafe_deserialization(node, func_name)
        
        # SSRF via requests
        if func_name and func_name.startswith("requests."):
            self._check_ssrf(node)
        
        # Prompt injection in LLM calls
        if func_name and any(x in func_name.lower() for x in 
                            ["openai", "anthropic", "completion", "chat", "generate"]):
            self._check_prompt_injection(node)
        
        # Eval/exec
        if func_name in {"eval", "exec", "compile"}:
            self._check_code_execution(node, func_name)
        
        self.generic_visit(node)
    
    def _check_sql_injection(self, node: ast.Call) -> None:
        """Check for SQL injection vulnerabilities."""
        if not node.args:
            return
        
        query_arg = node.args[0]
        
        # Check for f-strings
        if isinstance(query_arg, ast.JoinedStr):
            self._report_sql_injection(node, "f-string interpolation")
            return
        
        # Check for string formatting
        if isinstance(query_arg, ast.BinOp) and isinstance(query_arg.op, ast.Mod):
            self._report_sql_injection(node, "% string formatting")
            return
        
        # Check for .format() calls
        if isinstance(query_arg, ast.Call):
            if isinstance(query_arg.func, ast.Attribute) and query_arg.func.attr == "format":
                self._report_sql_injection(node, ".format() method")
                return
        
        # Check for string concatenation with tainted variables
        if isinstance(query_arg, ast.BinOp) and isinstance(query_arg.op, ast.Add):
            if self._contains_tainted_var(query_arg):
                self._report_sql_injection(node, "string concatenation with user input")
    
    def _report_sql_injection(self, node: ast.Call, method: str) -> None:
        """Report a SQL injection finding."""
        self.findings.append(Finding(
            rule_id="INJ001",
            title="SQL Injection Vulnerability",
            description=f"SQL query constructed using {method}. User-controlled data may be "
                       f"interpolated directly into the query, enabling SQL injection attacks.",
            severity=Severity.CRITICAL,
            category=Category.INJECTION,
            location=self._make_location(node),
            code_snippet=self._get_code_snippet(node.lineno, context=1),
            cwe_id="CWE-89",
            owasp_id="A03:2021",
            fix_suggestion="Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
            references=[
                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
            ],
        ))
    
    def _contains_tainted_var(self, node: ast.AST) -> bool:
        """Check if an expression contains a tainted variable."""
        if isinstance(node, ast.Name):
            return self.taint_ctx.is_tainted(node.id)
        elif isinstance(node, ast.BinOp):
            return self._contains_tainted_var(node.left) or self._contains_tainted_var(node.right)
        elif isinstance(node, ast.JoinedStr):
            return any(self._contains_tainted_var(v) for v in node.values 
                      if isinstance(v, ast.FormattedValue))
        elif isinstance(node, ast.FormattedValue):
            return self._contains_tainted_var(node.value)
        return False
    
    # === Command Injection Detection ===
    
    def _check_command_injection(self, node: ast.Call) -> None:
        """Check for command injection vulnerabilities."""
        func_name = self._get_full_attr_name(node.func)
        
        # os.system always takes a string - very dangerous
        if func_name == "os.system":
            if node.args and self._is_dynamic_string(node.args[0]):
                self.findings.append(Finding(
                    rule_id="INJ002",
                    title="Command Injection Vulnerability",
                    description="os.system() called with dynamically constructed command. "
                               "This is vulnerable to command injection if user input is included.",
                    severity=Severity.CRITICAL,
                    category=Category.INJECTION,
                    location=self._make_location(node),
                    code_snippet=self._get_code_snippet(node.lineno, context=1),
                    cwe_id="CWE-78",
                    owasp_id="A03:2021",
                    fix_suggestion="Use subprocess.run() with a list of arguments and shell=False",
                ))
        
        # subprocess with shell=True
        elif func_name and func_name.startswith("subprocess."):
            for kw in node.keywords:
                if kw.arg == "shell" and self._is_truthy(kw.value):
                    if node.args and self._is_dynamic_string(node.args[0]):
                        self.findings.append(Finding(
                            rule_id="INJ002",
                            title="Command Injection Vulnerability",
                            description="subprocess called with shell=True and dynamic command string. "
                                       "This enables command injection attacks.",
                            severity=Severity.CRITICAL,
                            category=Category.INJECTION,
                            location=self._make_location(node),
                            code_snippet=self._get_code_snippet(node.lineno, context=1),
                            cwe_id="CWE-78",
                            owasp_id="A03:2021",
                            fix_suggestion="Use shell=False with a list of arguments: subprocess.run(['cmd', arg1, arg2])",
                        ))
    
    def _is_dynamic_string(self, node: ast.AST) -> bool:
        """Check if a node represents a dynamically constructed string."""
        if isinstance(node, ast.JoinedStr):  # f-string
            return True
        if isinstance(node, ast.BinOp):  # concatenation or formatting
            return True
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
                return True
        if isinstance(node, ast.Name):
            return True  # Variable - could be dynamic
        return False
    
    def _is_truthy(self, node: ast.AST) -> bool:
        """Check if a node is a truthy constant."""
        if isinstance(node, ast.Constant):
            return bool(node.value)
        if isinstance(node, ast.NameConstant):  # Python 3.7
            return bool(node.value)
        return True  # Assume True if we can't determine
    
    # === Unsafe Deserialization ===
    
    def _check_unsafe_deserialization(self, node: ast.Call, func_name: str) -> None:
        """Check for unsafe deserialization."""
        severity = Severity.CRITICAL if "pickle" in func_name else Severity.HIGH
        
        # yaml.load without Loader is unsafe
        if func_name == "yaml.load":
            has_safe_loader = any(
                kw.arg == "Loader" and self._is_safe_yaml_loader(kw.value)
                for kw in node.keywords
            )
            if not has_safe_loader:
                self.findings.append(Finding(
                    rule_id="DES001",
                    title="Unsafe YAML Deserialization",
                    description="yaml.load() called without a safe Loader. This allows arbitrary "
                               "code execution through YAML deserialization attacks.",
                    severity=Severity.CRITICAL,
                    category=Category.DESERIALIZATION,
                    location=self._make_location(node),
                    code_snippet=self._get_code_snippet(node.lineno),
                    cwe_id="CWE-502",
                    fix_suggestion="Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader)",
                ))
        elif "pickle" in func_name:
            self.findings.append(Finding(
                rule_id="DES002",
                title="Unsafe Pickle Deserialization",
                description="Pickle deserialization of untrusted data enables arbitrary code execution. "
                           "Pickle should never be used with untrusted input.",
                severity=Severity.CRITICAL,
                category=Category.DESERIALIZATION,
                location=self._make_location(node),
                code_snippet=self._get_code_snippet(node.lineno),
                cwe_id="CWE-502",
                fix_suggestion="Use JSON or another safe serialization format for untrusted data",
            ))
    
    def _is_safe_yaml_loader(self, node: ast.AST) -> bool:
        """Check if a YAML loader is safe."""
        name = self._get_full_attr_name(node)
        return name in {"yaml.SafeLoader", "yaml.CSafeLoader", "SafeLoader", "CSafeLoader"}
    
    # === SSRF Detection ===
    
    def _check_ssrf(self, node: ast.Call) -> None:
        """Check for SSRF vulnerabilities."""
        if not node.args:
            return
        
        url_arg = node.args[0]
        
        if isinstance(url_arg, ast.Name) and self.taint_ctx.is_tainted(url_arg.id):
            self.findings.append(Finding(
                rule_id="SSRF001",
                title="Server-Side Request Forgery (SSRF)",
                description="HTTP request made with user-controlled URL. Attackers can use this "
                           "to access internal services or scan internal networks.",
                severity=Severity.HIGH,
                category=Category.SSRF,
                location=self._make_location(node),
                code_snippet=self._get_code_snippet(node.lineno),
                cwe_id="CWE-918",
                owasp_id="A10:2021",
                fix_suggestion="Validate and sanitize URLs. Use allowlists for permitted domains.",
            ))
        elif self._is_dynamic_string(url_arg):
            self.findings.append(Finding(
                rule_id="SSRF001",
                title="Potential Server-Side Request Forgery (SSRF)",
                description="HTTP request made with dynamically constructed URL. If user input "
                           "is included, this may enable SSRF attacks.",
                severity=Severity.MEDIUM,
                category=Category.SSRF,
                location=self._make_location(node),
                code_snippet=self._get_code_snippet(node.lineno),
                cwe_id="CWE-918",
                confidence=0.7,
            ))
    
    # === Prompt Injection Detection ===
    
    def _check_prompt_injection(self, node: ast.Call) -> None:
        """Check for prompt injection vulnerabilities in LLM calls."""
        if not self.config.detect_prompt_injection:
            return
        
        # Look for message/prompt arguments
        for arg in node.args:
            if self._check_prompt_arg_for_injection(arg):
                return
        
        for kw in node.keywords:
            if kw.arg in {"prompt", "messages", "content", "text", "input"}:
                if self._check_prompt_arg_for_injection(kw.value):
                    return
    
    def _check_prompt_arg_for_injection(self, node: ast.AST) -> bool:
        """Check a prompt argument for injection risks."""
        # f-string with variables
        if isinstance(node, ast.JoinedStr):
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    if isinstance(value.value, ast.Name):
                        var_name = value.value.id.lower()
                        # Check for obvious user input variable names
                        if any(x in var_name for x in ["user", "input", "query", "message", "request"]):
                            self._report_prompt_injection(node, "user input variable in f-string prompt")
                            return True
                        # Check taint tracking
                        if self.taint_ctx.is_tainted(value.value.id):
                            self._report_prompt_injection(node, "tainted variable in prompt")
                            return True
        
        # String concatenation
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            if self._contains_tainted_var(node):
                self._report_prompt_injection(node, "concatenation with user input")
                return True
        
        # .format() call
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
                for arg in node.args:
                    if isinstance(arg, ast.Name) and self.taint_ctx.is_tainted(arg.id):
                        self._report_prompt_injection(node, ".format() with user input")
                        return True
        
        return False
    
    def _report_prompt_injection(self, node: ast.AST, method: str) -> None:
        """Report a prompt injection finding."""
        self.findings.append(Finding(
            rule_id="PRI001",
            title="Prompt Injection Vulnerability",
            description=f"User input directly embedded in LLM prompt via {method}. "
                       f"Attackers can inject malicious instructions to manipulate the AI's behavior, "
                       f"extract system prompts, or perform unauthorized actions.",
            severity=Severity.HIGH,
            category=Category.PROMPT_INJECTION,
            location=self._make_location(node),
            code_snippet=self._get_code_snippet(node.lineno, context=1),
            cwe_id="CWE-74",
            fix_suggestion=(
                "1. Separate system prompts from user content using message roles\n"
                "2. Sanitize user input (remove control characters, limit length)\n"
                "3. Use structured output formats to detect injection attempts\n"
                "4. Consider input validation with allowlists for expected formats"
            ),
            references=[
                "https://owasp.org/www-project-top-10-for-large-language-model-applications/"
            ],
        ))
    
    # === Code Execution Detection ===
    
    def _check_code_execution(self, node: ast.Call, func_name: str) -> None:
        """Check for dangerous code execution."""
        if node.args and self._is_dynamic_string(node.args[0]):
            self.findings.append(Finding(
                rule_id="INJ003",
                title=f"Dangerous {func_name}() Usage",
                description=f"{func_name}() called with dynamic string. This allows arbitrary "
                           f"code execution if user input is included.",
                severity=Severity.CRITICAL,
                category=Category.INJECTION,
                location=self._make_location(node),
                code_snippet=self._get_code_snippet(node.lineno),
                cwe_id="CWE-95",
                fix_suggestion=f"Avoid {func_name}() with user input. Use safer alternatives like ast.literal_eval() for data parsing.",
            ))
    
    # === Function/Class Context Tracking ===
    
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Track function context."""
        old_function = self.current_function
        self.current_function = node.name
        self.generic_visit(node)
        self.current_function = old_function
    
    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Track async function context."""
        old_function = self.current_function
        self.current_function = node.name
        self.generic_visit(node)
        self.current_function = old_function
    
    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Track class context."""
        old_class = self.in_class
        self.in_class = node.name
        self.generic_visit(node)
        self.in_class = old_class
