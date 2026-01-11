"""Example vulnerable code demonstrating AI-generated security issues.

DO NOT USE THIS CODE IN PRODUCTION - it contains intentional vulnerabilities
for testing and demonstration purposes.
"""

import os
import subprocess
import base64

# SEC001: Hardcoded API Keys (common in AI-generated code)
OPENAI_API_KEY = "sk-proj-abc123def456ghi789jkl012mno345pqr678"
anthropic_key = "sk-ant-abc123-xyz789"

# SEC002: Hardcoded password
DATABASE_PASSWORD = "super_secret_password_123"

# SEC003: Hardcoded connection string
db_url = "postgresql://admin:password123@localhost:5432/mydb"


def get_user(user_id):
    """INJ001: SQL Injection via f-string (very common in AI code)."""
    query = f"SELECT * FROM users WHERE id = {user_id}"
    # cursor.execute(query)  # Vulnerable!
    return query


def search_users(name):
    """INJ001: SQL Injection via string concatenation."""
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    return query


def run_command(filename):
    """INJ002: Command injection via os.system."""
    os.system(f"cat {filename}")  # Attacker can inject: "; rm -rf /"


def process_file(user_path):
    """INJ002: Command injection via subprocess with shell=True."""
    subprocess.run(f"process {user_path}", shell=True)


def read_user_file(filename):
    """INJ003: Path traversal vulnerability."""
    # Attacker can use: "../../../etc/passwd"
    filepath = f"/uploads/{filename}"
    with open(filepath) as f:
        return f.read()


def chat_with_ai(user_input):
    """PRI001: Prompt injection - user input directly in prompt."""
    prompt = f"You are a helpful assistant. The user says: {user_input}"
    # client.chat(prompt)  # Vulnerable to prompt injection!
    return prompt


def build_system_prompt(user_query):
    """PRI001: Another prompt injection pattern."""
    system = "You are a customer service bot."
    message = f"{system} Answer this question: {user_query}"
    return message


def log_environment():
    """EXF004: Environment variable exposure."""
    print(os.environ)  # Leaks all env vars including secrets


def send_data(password):
    """EXF002: Suspicious encoding of sensitive data."""
    encoded = base64.b64encode(password.encode())
    return encoded


# This file intentionally contains security vulnerabilities for testing.
# Run: ai-code-guard scan examples/ to see them detected.
