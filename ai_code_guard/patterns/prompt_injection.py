"""Prompt injection vulnerability detection patterns.

These patterns detect security issues specific to LLM/AI integrations,
particularly where user input could be used to manipulate AI behavior.
"""

import re
from typing import List

from .base import BasePattern, Finding, Severity


class PromptInjectionUserInputPattern(BasePattern):
    """Detect user input directly concatenated into LLM prompts."""
    
    rule_id = "PRI001"
    name = "Prompt Injection: User Input in Prompt"
    description = (
        "User input is directly concatenated or formatted into an LLM prompt. "
        "Attackers can inject malicious instructions to manipulate AI behavior."
    )
    severity = Severity.HIGH
    
    # Patterns that indicate prompt construction with user input
    PROMPT_PATTERNS = [
        # f-string patterns
        (r'(prompt|system|message|instruction)\s*=\s*f["\'].*\{.*(?:user|input|query|question|text|message|content).*\}.*["\']', 
         "User variable interpolated in f-string prompt"),
        
        # .format() patterns  
        (r'(prompt|system|message|instruction)\s*=\s*["\'].*\{\}.*["\']\.format\s*\(.*(?:user|input|query).*\)',
         "User input passed to .format() for prompt"),
        
        # String concatenation
        (r'(prompt|system|message)\s*=.*\+\s*(?:user_input|user_message|query|user_query)',
         "User input concatenated to prompt string"),
        
        # Template string with user input (JavaScript/TypeScript)
        (r'(prompt|system|message)\s*=\s*`.*\$\{.*(?:user|input|query).*\}.*`',
         "User variable in template literal prompt"),
        
        # Common AI SDK patterns
        (r'messages\s*=\s*\[.*\{["\']role["\']:\s*["\']user["\'].*\{.*(?:user|input).*\}',
         "Unsanitized user input in messages array"),
    ]
    
    def scan(self, content: str, filepath: str) -> List[Finding]:
        findings = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            for pattern, message in self.PROMPT_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(self._create_finding(
                        filepath=filepath,
                        line_number=line_num,
                        code_snippet=line,
                        message=message,
                        fix_suggestion=(
                            "Sanitize user input before including in prompts. "
                            "Use structured prompt templates with clear boundaries. "
                            "Consider using XML tags or delimiters to separate user input: "
                            '`<user_input>{sanitized_input}</user_input>`'
                        ),
                    ))
        
        return findings


class PromptInjectionSystemPromptPattern(BasePattern):
    """Detect patterns where system prompts might be exposed or manipulated."""
    
    rule_id = "PRI002"
    name = "Prompt Injection: System Prompt Exposure Risk"
    description = (
        "System prompt or instructions stored in a way that might be "
        "exposed to users or manipulated through indirect injection."
    )
    severity = Severity.MEDIUM
    
    EXPOSURE_PATTERNS = [
        # System prompt in client-side code
        (r'(SYSTEM_PROMPT|systemPrompt|system_instruction)\s*=\s*["\']',
         "System prompt defined as string constant - may be exposed in client bundle"),
        
        # System prompt in environment that might leak
        (r'system.*prompt.*=.*os\.environ|process\.env.*system.*prompt',
         "System prompt from environment - ensure not logged or exposed"),
        
        # Printing/logging system prompts
        (r'(print|console\.log|logger\.|logging\.)\s*\(.*system.*prompt',
         "System prompt being logged - potential information disclosure"),
    ]
    
    def scan(self, content: str, filepath: str) -> List[Finding]:
        findings = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            for pattern, message in self.EXPOSURE_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(self._create_finding(
                        filepath=filepath,
                        line_number=line_num,
                        code_snippet=line,
                        message=message,
                        fix_suggestion=(
                            "Store system prompts server-side only. "
                            "Never log or expose system prompts to users. "
                            "Use secure configuration management for prompt templates."
                        ),
                    ))
        
        return findings


class PromptInjectionNoSanitizationPattern(BasePattern):
    """Detect LLM API calls without apparent input sanitization."""
    
    rule_id = "PRI003"
    name = "Prompt Injection: Missing Input Sanitization"
    description = (
        "LLM API call detected without apparent input sanitization. "
        "User input should be validated and sanitized before sending to LLMs."
    )
    severity = Severity.MEDIUM
    
    # Common LLM API patterns
    LLM_API_PATTERNS = [
        r'openai\.ChatCompletion\.create',
        r'openai\.chat\.completions\.create',
        r'client\.chat\.completions\.create',
        r'anthropic\.messages\.create',
        r'client\.messages\.create',
        r'cohere\.generate',
        r'replicate\.run',
        r'\.generate\s*\(',
        r'\.complete\s*\(',
        r'\.chat\s*\(',
    ]
    
    # Sanitization patterns we look for
    SANITIZATION_PATTERNS = [
        r'sanitize',
        r'escape',
        r'validate',
        r'clean',
        r'filter',
        r'strip',
        r'encode',
    ]
    
    def scan(self, content: str, filepath: str) -> List[Finding]:
        findings = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            # Check if this line has an LLM API call
            has_llm_call = any(re.search(p, line, re.IGNORECASE) for p in self.LLM_API_PATTERNS)
            if not has_llm_call:
                continue
            
            # Look for sanitization in surrounding context (5 lines before)
            start = max(0, line_num - 6)
            context = '\n'.join(lines[start:line_num])
            
            has_sanitization = any(
                re.search(p, context, re.IGNORECASE) 
                for p in self.SANITIZATION_PATTERNS
            )
            
            if not has_sanitization:
                findings.append(self._create_finding(
                    filepath=filepath,
                    line_number=line_num,
                    code_snippet=line,
                    message="LLM API call without visible input sanitization in preceding code",
                    fix_suggestion=(
                        "Add input sanitization before LLM API calls:\n"
                        "  1. Validate input length and format\n"
                        "  2. Remove or escape special characters\n"
                        "  3. Check for injection patterns\n"
                        "  4. Use allowlists for expected input types"
                    ),
                ))
        
        return findings


class PromptInjectionJailbreakPattern(BasePattern):
    """Detect patterns that might indicate jailbreak attempts in stored prompts."""
    
    rule_id = "PRI004"
    name = "Prompt Injection: Potential Jailbreak Pattern"
    description = (
        "Code contains strings that match known jailbreak patterns. "
        "This might be test code, but could also indicate malicious prompts."
    )
    severity = Severity.LOW
    
    JAILBREAK_INDICATORS = [
        r'ignore\s+(previous|all|above)\s+instructions',
        r'disregard\s+(your|all)\s+(rules|instructions)',
        r'you\s+are\s+now\s+(DAN|jailbroken|unrestricted)',
        r'pretend\s+you\s+(are|have)\s+no\s+(restrictions|limits)',
        r'override\s+(your|system)\s+prompt',
        r'bypass\s+(your|the)\s+(filters|restrictions)',
        r'act\s+as\s+if\s+you\s+have\s+no\s+guidelines',
    ]
    
    def scan(self, content: str, filepath: str) -> List[Finding]:
        findings = []
        
        for pattern in self.JAILBREAK_INDICATORS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_number = self._get_line_number(content, match.start())
                line = self._get_line_at(content, line_number)
                
                findings.append(self._create_finding(
                    filepath=filepath,
                    line_number=line_number,
                    code_snippet=line,
                    message=f"Potential jailbreak pattern detected: '{match.group()}'",
                    fix_suggestion=(
                        "If this is test code, consider moving to a separate test directory. "
                        "If this is user-facing code, ensure these patterns are filtered from input."
                    ),
                ))
        
        return findings


# Export all patterns
PROMPT_INJECTION_PATTERNS = [
    PromptInjectionUserInputPattern,
    PromptInjectionSystemPromptPattern,
    PromptInjectionNoSanitizationPattern,
    PromptInjectionJailbreakPattern,
]
