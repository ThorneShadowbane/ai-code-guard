"""
Specialized prompt injection detection for LLM applications.

This analyzer detects vulnerabilities specific to AI/LLM integrations,
including direct prompt injection, indirect injection risks, and 
unsafe prompt construction patterns.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from ..models import Category, Config, Finding, Location, Severity


@dataclass
class PromptPattern:
    """Pattern for detecting prompt injection vulnerabilities."""
    
    rule_id: str
    name: str
    pattern: re.Pattern[str]
    severity: Severity
    description: str
    fix_suggestion: str
    confidence: float = 1.0


# LLM API patterns - detect when LLM APIs are being used
LLM_API_PATTERNS = [
    # OpenAI
    re.compile(r'openai\.(?:Chat)?Completion\.create|client\.chat\.completions\.create', re.I),
    re.compile(r'openai\.(?:Embedding|Image|Audio)', re.I),
    # Anthropic
    re.compile(r'anthropic\.(?:Anthropic|Client)|client\.messages\.create', re.I),
    # LangChain
    re.compile(r'(?:Chat)?(?:OpenAI|Anthropic|Cohere|HuggingFace)\(', re.I),
    re.compile(r'LLMChain|ConversationChain|RetrievalQA', re.I),
    # Generic
    re.compile(r'\.generate\(|\.complete\(|\.chat\(', re.I),
]

# Variables that typically contain user input
USER_INPUT_VARS = re.compile(
    r'\b(?:user_?(?:input|message|query|prompt|text|content|data|request)|'
    r'input_?(?:text|data|message|query)|'
    r'query|message|prompt|question|request(?:_data)?|'
    r'form(?:_data)?|body|payload)\b',
    re.I
)

# Patterns that indicate unsafe prompt construction
PROMPT_PATTERNS: list[PromptPattern] = [
    PromptPattern(
        rule_id="PRI001",
        name="Direct Prompt Injection - F-String",
        pattern=re.compile(
            r'(?:system_?)?(?:prompt|message|content)\s*=\s*f["\'][^"\']*\{[^}]*(?:user|input|query|message|request)',
            re.I
        ),
        severity=Severity.HIGH,
        description="User input directly interpolated into prompt using f-string. "
                   "Attackers can inject malicious instructions.",
        fix_suggestion="Use separate user/assistant message roles. Sanitize and validate user input.",
    ),
    PromptPattern(
        rule_id="PRI001",
        name="Direct Prompt Injection - Format String",
        pattern=re.compile(
            r'(?:system_?)?(?:prompt|message|content)\s*=\s*["\'][^"\']*\{[^}]*\}[^"\']*["\']\.format\(',
            re.I
        ),
        severity=Severity.HIGH,
        description="User input interpolated into prompt using .format(). "
                   "This enables prompt injection attacks.",
        fix_suggestion="Use separate message roles and input validation.",
    ),
    PromptPattern(
        rule_id="PRI001",
        name="Direct Prompt Injection - Concatenation",
        pattern=re.compile(
            r'(?:system_?)?(?:prompt|message|content)\s*=\s*["\'][^"\']+["\']\s*\+\s*(?:user|input|query|message)',
            re.I
        ),
        severity=Severity.HIGH,
        description="User input concatenated directly into prompt string. "
                   "Classic prompt injection vulnerability.",
        fix_suggestion="Never concatenate user input into prompts. Use structured message formats.",
    ),
    PromptPattern(
        rule_id="PRI001",
        name="Direct Prompt Injection - Percent Format",
        pattern=re.compile(
            r'(?:system_?)?(?:prompt|message|content)\s*=\s*["\'][^"\']*%[sd][^"\']*["\']\s*%',
            re.I
        ),
        severity=Severity.HIGH,
        description="User input interpolated using % string formatting. "
                   "Enables prompt injection attacks.",
        fix_suggestion="Use structured message formats with proper role separation.",
    ),
    PromptPattern(
        rule_id="PRI002",
        name="System Prompt with User Data",
        pattern=re.compile(
            r'(?:"role"\s*:\s*"system"|role\s*=\s*["\']system["\'])[^}]*(?:user|input|query|data)',
            re.I
        ),
        severity=Severity.HIGH,
        description="User-controlled data may be included in system prompt. "
                   "System prompts should contain only trusted content.",
        fix_suggestion="Keep system prompts static. Put user data in 'user' role messages only.",
    ),
    PromptPattern(
        rule_id="PRI003",
        name="Unsafe Template Rendering",
        pattern=re.compile(
            r'(?:jinja2?|mako|django)\.(?:Template|Environment)\([^)]*\)\.render\([^)]*(?:user|input|query)',
            re.I
        ),
        severity=Severity.HIGH,
        description="Template engine used to render prompts with user input. "
                   "May enable both template injection and prompt injection.",
        fix_suggestion="Avoid template engines for prompts. Use simple string formatting with sanitization.",
    ),
    PromptPattern(
        rule_id="PRI004",
        name="LangChain Prompt Template with User Input",
        pattern=re.compile(
            r'PromptTemplate\([^)]*(?:input_variables|partial_variables)[^)]*\)',
            re.I
        ),
        severity=Severity.MEDIUM,
        description="LangChain PromptTemplate detected. Ensure user inputs are properly validated "
                   "before being passed to the template.",
        fix_suggestion="Add input validation. Consider using OutputParsers for structured responses.",
        confidence=0.7,
    ),
    PromptPattern(
        rule_id="PRI005",
        name="Raw User Input to LLM",
        pattern=re.compile(
            r'(?:messages|prompt)\s*=\s*\[\s*\{[^}]*(?:content|text)\s*:\s*(?:user_input|input|query|message)\b',
            re.I
        ),
        severity=Severity.MEDIUM,
        description="User input passed directly as message content without apparent sanitization.",
        fix_suggestion="Sanitize user input: limit length, strip control characters, validate format.",
        confidence=0.8,
    ),
]

# Patterns that indicate good security practices (reduce false positives)
SAFE_PATTERNS = [
    re.compile(r'sanitize|escape|validate|clean|filter', re.I),
    re.compile(r'max_length|truncate|[:]\d+\]', re.I),  # Length limiting
    re.compile(r'html\.escape|bleach\.clean|markupsafe', re.I),
    re.compile(r'input_validator|ContentFilter', re.I),
]


class PromptInjectionAnalyzer:
    """
    Specialized analyzer for prompt injection vulnerabilities.
    
    This goes beyond simple regex matching to understand the context
    of LLM API usage and detect various injection patterns.
    """
    
    def __init__(self, filepath: Path, content: str, config: Config):
        self.filepath = filepath
        self.content = content
        self.lines = content.splitlines()
        self.config = config
        
        # Track context
        self.uses_llm_api = self._detect_llm_usage()
        self.has_sanitization = self._detect_sanitization()
    
    def _detect_llm_usage(self) -> bool:
        """Detect if file uses LLM APIs."""
        for pattern in LLM_API_PATTERNS:
            if pattern.search(self.content):
                return True
        return False
    
    def _detect_sanitization(self) -> bool:
        """Detect if file has sanitization functions."""
        for pattern in SAFE_PATTERNS:
            if pattern.search(self.content):
                return True
        return False
    
    def analyze(self) -> list[Finding]:
        """Run prompt injection analysis."""
        if not self.config.detect_prompt_injection:
            return []
        
        findings: list[Finding] = []
        
        # Only analyze files that use LLM APIs
        if not self.uses_llm_api:
            # Still check for obvious prompt construction patterns
            findings.extend(self._basic_pattern_scan())
            return findings
        
        # Full analysis for LLM-using files
        findings.extend(self._pattern_scan())
        findings.extend(self._context_aware_scan())
        
        return findings
    
    def _basic_pattern_scan(self) -> Iterator[Finding]:
        """Basic pattern matching for files without detected LLM usage."""
        # Only check highest-confidence patterns
        for pattern in PROMPT_PATTERNS:
            if pattern.confidence < 0.9:
                continue
            
            for line_num, line in enumerate(self.lines, start=1):
                if pattern.pattern.search(line):
                    yield self._create_finding(pattern, line_num, line)
    
    def _pattern_scan(self) -> Iterator[Finding]:
        """Full pattern matching scan."""
        for pattern in PROMPT_PATTERNS:
            if pattern.rule_id in self.config.disabled_rules:
                continue
            
            for line_num, line in enumerate(self.lines, start=1):
                if pattern.pattern.search(line):
                    # Check for nearby sanitization
                    confidence = pattern.confidence
                    if self._has_nearby_sanitization(line_num):
                        confidence *= 0.5
                    
                    if confidence >= 0.5:
                        yield self._create_finding(
                            pattern, line_num, line, confidence=confidence
                        )
    
    def _context_aware_scan(self) -> Iterator[Finding]:
        """Context-aware scanning that looks at surrounding code."""
        # Find all user input variable assignments
        user_vars = self._find_user_input_vars()
        
        # Track these variables through the code
        for var_name, var_line in user_vars:
            # Look for usage in prompt construction
            for line_num, line in enumerate(self.lines, start=1):
                if line_num <= var_line:
                    continue  # Only check after assignment
                
                # Check if variable is used in prompt context
                if self._is_prompt_context(line) and var_name in line:
                    if not self._has_nearby_sanitization(line_num):
                        yield Finding(
                            rule_id="PRI006",
                            title="User Input Variable in Prompt",
                            description=f"Variable '{var_name}' (assigned from user input at line {var_line}) "
                                       f"is used in prompt construction without apparent sanitization.",
                            severity=Severity.MEDIUM,
                            category=Category.PROMPT_INJECTION,
                            location=Location(
                                filepath=self.filepath,
                                line=line_num,
                                column=line.find(var_name),
                            ),
                            code_snippet=self._get_context(line_num, 2),
                            fix_suggestion="Sanitize the variable before use: limit length, remove special characters.",
                            confidence=0.7,
                        )
    
    def _find_user_input_vars(self) -> list[tuple[str, int]]:
        """Find variables that are assigned from user input."""
        results: list[tuple[str, int]] = []
        
        # Pattern for assignment from request/input
        assignment_pattern = re.compile(
            r'(\w+)\s*=\s*(?:request\.(?:json|form|args|data)|'
            r'input\(|sys\.stdin|os\.environ)',
            re.I
        )
        
        for line_num, line in enumerate(self.lines, start=1):
            match = assignment_pattern.search(line)
            if match:
                results.append((match.group(1), line_num))
        
        return results
    
    def _is_prompt_context(self, line: str) -> bool:
        """Check if a line is in a prompt construction context."""
        prompt_indicators = [
            'prompt', 'message', 'content', 'system', 'assistant', 'user',
            'template', 'instruction', 'completion', '.create('
        ]
        line_lower = line.lower()
        return any(indicator in line_lower for indicator in prompt_indicators)
    
    def _has_nearby_sanitization(self, line_num: int, window: int = 5) -> bool:
        """Check if there's sanitization code near a line."""
        start = max(0, line_num - window - 1)
        end = min(len(self.lines), line_num + window)
        
        for i in range(start, end):
            for pattern in SAFE_PATTERNS:
                if pattern.search(self.lines[i]):
                    return True
        
        return False
    
    def _get_context(self, line_num: int, context: int = 1) -> str:
        """Get code context around a line."""
        start = max(0, line_num - context - 1)
        end = min(len(self.lines), line_num + context)
        return "\n".join(self.lines[start:end])
    
    def _create_finding(
        self,
        pattern: PromptPattern,
        line_num: int,
        line: str,
        confidence: float | None = None,
    ) -> Finding:
        """Create a Finding from a pattern match."""
        return Finding(
            rule_id=pattern.rule_id,
            title=pattern.name,
            description=pattern.description,
            severity=pattern.severity,
            category=Category.PROMPT_INJECTION,
            location=Location(
                filepath=self.filepath,
                line=line_num,
                column=0,
            ),
            code_snippet=line.strip(),
            cwe_id="CWE-74",
            owasp_id="LLM01",  # OWASP LLM Top 10
            fix_suggestion=pattern.fix_suggestion,
            confidence=confidence or pattern.confidence,
            references=[
                "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
                "https://www.lakera.ai/blog/prompt-injection",
            ],
        )


class IndirectInjectionAnalyzer:
    """
    Analyzer for indirect prompt injection vulnerabilities.
    
    Detects patterns where external data (files, web content, database)
    is loaded and passed to LLMs without sanitization.
    """
    
    def __init__(self, filepath: Path, content: str, config: Config):
        self.filepath = filepath
        self.content = content
        self.lines = content.splitlines()
        self.config = config
    
    def analyze(self) -> list[Finding]:
        """Run indirect injection analysis."""
        findings: list[Finding] = []
        
        # Detect RAG patterns
        findings.extend(self._detect_rag_injection())
        
        # Detect web content injection
        findings.extend(self._detect_web_content_injection())
        
        return findings
    
    def _detect_rag_injection(self) -> Iterator[Finding]:
        """Detect potential injection via RAG/retrieval systems."""
        # Patterns indicating document loading
        doc_load_patterns = [
            (re.compile(r'\.load_documents?\(|DocumentLoader|TextLoader', re.I), "document loader"),
            (re.compile(r'\.similarity_search\(|\.retrieve\(|retriever\.', re.I), "vector search"),
            (re.compile(r'BeautifulSoup|\.get_text\(\)|\.extract\(\)', re.I), "web scraping"),
        ]
        
        for line_num, line in enumerate(self.lines, start=1):
            for pattern, source_type in doc_load_patterns:
                if pattern.search(line):
                    # Check if this feeds into an LLM call
                    if self._feeds_to_llm(line_num):
                        yield Finding(
                            rule_id="PRI010",
                            title="Potential Indirect Prompt Injection",
                            description=f"Data from {source_type} may be passed to LLM. "
                                       f"External documents can contain malicious instructions.",
                            severity=Severity.MEDIUM,
                            category=Category.PROMPT_INJECTION,
                            location=Location(filepath=self.filepath, line=line_num),
                            code_snippet=line.strip(),
                            fix_suggestion="Sanitize retrieved content before passing to LLM. "
                                         "Consider content filtering and length limits.",
                            confidence=0.6,
                        )
    
    def _detect_web_content_injection(self) -> Iterator[Finding]:
        """Detect injection via web content."""
        web_patterns = [
            re.compile(r'requests\.get\(|urllib\.request|httpx\.get', re.I),
            re.compile(r'\.read\(\)|\.text|\.content|\.json\(\)', re.I),
        ]
        
        for line_num, line in enumerate(self.lines, start=1):
            if any(p.search(line) for p in web_patterns):
                if self._feeds_to_llm(line_num):
                    yield Finding(
                        rule_id="PRI011",
                        title="Web Content to LLM Risk",
                        description="Web content fetched and potentially passed to LLM. "
                                   "Malicious web pages can contain prompt injection payloads.",
                        severity=Severity.MEDIUM,
                        category=Category.PROMPT_INJECTION,
                        location=Location(filepath=self.filepath, line=line_num),
                        code_snippet=line.strip(),
                        fix_suggestion="Sanitize web content. Strip HTML/scripts. Limit content length.",
                        confidence=0.5,
                    )
    
    def _feeds_to_llm(self, start_line: int, window: int = 20) -> bool:
        """Check if data from a line feeds into an LLM call."""
        end = min(len(self.lines), start_line + window)
        
        for i in range(start_line, end):
            line = self.lines[i]
            for pattern in LLM_API_PATTERNS:
                if pattern.search(line):
                    return True
        
        return False
