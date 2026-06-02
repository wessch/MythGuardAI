"""JavaScript/TypeScript analyzer for MythGuardAI.

Analyzes JavaScript and TypeScript source code to discover
capabilities using regex-based pattern matching. A future version
may integrate tree-sitter for full AST analysis.

Detection coverage:
- child_process.exec, child_process.spawn, child_process.fork
- fs.readFile, fs.writeFile, fs.appendFile, fs.unlink, fs.mkdir, etc.
- fetch, XMLHttpRequest, axios, node-fetch
- eval(), Function(), new Function()
- require() for sensitive modules
- process.env access
- crypto operations
- net/http server creation
"""

from __future__ import annotations

import re
from typing import Any

from mythguardai.models import (
    Capability,
    CapabilityCategory,
    ReachabilityStatus,
    SourceLocation,
)


# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------

# Each pattern is (compiled_regex, category, description, confidence)
_CALL_PATTERNS: list[tuple[re.Pattern, CapabilityCategory, str, float]] = [
    # Subprocess execution
    (
        re.compile(r"child_process\s*\.\s*exec(?:Sync)?\s*\("),
        CapabilityCategory.SUBPROCESS,
        "Shell command execution via child_process.exec",
        0.95,
    ),
    (
        re.compile(r"child_process\s*\.\s*spawn(?:Sync)?\s*\("),
        CapabilityCategory.SUBPROCESS,
        "Process spawning via child_process.spawn",
        0.95,
    ),
    (
        re.compile(r"child_process\s*\.\s*fork\s*\("),
        CapabilityCategory.SUBPROCESS,
        "Process forking via child_process.fork",
        0.95,
    ),
    (
        re.compile(r"child_process\s*\.\s*execFile(?:Sync)?\s*\("),
        CapabilityCategory.SUBPROCESS,
        "File execution via child_process.execFile",
        0.95,
    ),
    (
        re.compile(r"require\s*\(\s*['\"]child_process['\"]\s*\)"),
        CapabilityCategory.SUBPROCESS,
        "Import of child_process module",
        0.7,
    ),
    # File system - read
    (
        re.compile(r"fs\s*\.\s*readFile(?:Sync)?\s*\("),
        CapabilityCategory.FILE_READ,
        "File read via fs.readFile",
        0.95,
    ),
    (
        re.compile(r"fs\s*\.\s*readdir(?:Sync)?\s*\("),
        CapabilityCategory.FILE_READ,
        "Directory listing via fs.readdir",
        0.95,
    ),
    (
        re.compile(r"fs\s*\.\s*readlink(?:Sync)?\s*\("),
        CapabilityCategory.FILE_READ,
        "Symlink read via fs.readlink",
        0.90,
    ),
    (
        re.compile(r"fs\s*\.\s*stat(?:Sync)?\s*\("),
        CapabilityCategory.FILE_READ,
        "File stat via fs.stat",
        0.85,
    ),
    (
        re.compile(r"fs\s*\.\s*existsSync\s*\("),
        CapabilityCategory.FILE_READ,
        "File existence check via fs.existsSync",
        0.80,
    ),
    # File system - write
    (
        re.compile(r"fs\s*\.\s*writeFile(?:Sync)?\s*\("),
        CapabilityCategory.FILE_WRITE,
        "File write via fs.writeFile",
        0.95,
    ),
    (
        re.compile(r"fs\s*\.\s*appendFile(?:Sync)?\s*\("),
        CapabilityCategory.FILE_WRITE,
        "File append via fs.appendFile",
        0.95,
    ),
    (
        re.compile(r"fs\s*\.\s*unlink(?:Sync)?\s*\("),
        CapabilityCategory.FILE_WRITE,
        "File deletion via fs.unlink",
        0.95,
    ),
    (
        re.compile(r"fs\s*\.\s*mkdir(?:Sync)?\s*\("),
        CapabilityCategory.FILE_WRITE,
        "Directory creation via fs.mkdir",
        0.95,
    ),
    (
        re.compile(r"fs\s*\.\s*rmdir(?:Sync)?\s*\("),
        CapabilityCategory.FILE_WRITE,
        "Directory removal via fs.rmdir",
        0.95,
    ),
    (
        re.compile(r"fs\s*\.\s*rename(?:Sync)?\s*\("),
        CapabilityCategory.FILE_WRITE,
        "File rename via fs.rename",
        0.90,
    ),
    (
        re.compile(r"fs\s*\.\s*chmod(?:Sync)?\s*\("),
        CapabilityCategory.PRIVILEGE_ESCALATION,
        "File permission change via fs.chmod",
        0.95,
    ),
    (
        re.compile(r"fs\s*\.\s*chown(?:Sync)?\s*\("),
        CapabilityCategory.PRIVILEGE_ESCALATION,
        "File ownership change via fs.chown",
        0.95,
    ),
    (
        re.compile(r"require\s*\(\s*['\"]fs['\"]\s*\)"),
        CapabilityCategory.FILE_READ,
        "Import of fs module",
        0.6,
    ),
    (
        re.compile(r"require\s*\(\s*['\"]fs/promises['\"]\s*\)"),
        CapabilityCategory.FILE_READ,
        "Import of fs/promises module",
        0.6,
    ),
    # Network client
    (
        re.compile(r"\bfetch\s*\("),
        CapabilityCategory.NETWORK_CLIENT,
        "HTTP request via fetch()",
        0.95,
    ),
    (
        re.compile(r"new\s+XMLHttpRequest\s*\("),
        CapabilityCategory.NETWORK_CLIENT,
        "HTTP request via XMLHttpRequest",
        0.95,
    ),
    (
        re.compile(r"axios\s*\.\s*(?:get|post|put|delete|patch|head)\s*\("),
        CapabilityCategory.NETWORK_CLIENT,
        "HTTP request via axios",
        0.95,
    ),
    (
        re.compile(r"require\s*\(\s*['\"]node-fetch['\"]\s*\)"),
        CapabilityCategory.NETWORK_CLIENT,
        "Import of node-fetch module",
        0.7,
    ),
    (
        re.compile(r"require\s*\(\s*['\"]axios['\"]\s*\)"),
        CapabilityCategory.NETWORK_CLIENT,
        "Import of axios module",
        0.7,
    ),
    (
        re.compile(r"http\s*\.\s*request\s*\("),
        CapabilityCategory.NETWORK_CLIENT,
        "HTTP request via http.request",
        0.90,
    ),
    (
        re.compile(r"https\s*\.\s*request\s*\("),
        CapabilityCategory.NETWORK_CLIENT,
        "HTTPS request via https.request",
        0.90,
    ),
    # Network server
    (
        re.compile(r"http\s*\.\s*createServer\s*\("),
        CapabilityCategory.NETWORK_SERVER,
        "HTTP server creation via http.createServer",
        0.95,
    ),
    (
        re.compile(r"https\s*\.\s*createServer\s*\("),
        CapabilityCategory.NETWORK_SERVER,
        "HTTPS server creation via https.createServer",
        0.95,
    ),
    (
        re.compile(r"net\s*\.\s*createServer\s*\("),
        CapabilityCategory.NETWORK_SERVER,
        "TCP server creation via net.createServer",
        0.95,
    ),
    (
        re.compile(r"\.listen\s*\("),
        CapabilityCategory.NETWORK_SERVER,
        "Server listen call",
        0.70,
    ),
    # Dynamic execution
    (
        re.compile(r"\beval\s*\("),
        CapabilityCategory.DYNAMIC_EXEC,
        "Dynamic code evaluation via eval()",
        0.95,
    ),
    (
        re.compile(r"new\s+Function\s*\("),
        CapabilityCategory.DYNAMIC_EXEC,
        "Dynamic function creation via new Function()",
        0.95,
    ),
    # Environment access
    (
        re.compile(r"process\.env"),
        CapabilityCategory.ENVIRONMENT_READ,
        "Environment variable access via process.env",
        0.90,
    ),
    # Crypto
    (
        re.compile(r"require\s*\(\s*['\"]crypto['\"]\s*\)"),
        CapabilityCategory.CRYPTO,
        "Import of crypto module",
        0.7,
    ),
    (
        re.compile(r"crypto\s*\.\s*createHash\s*\("),
        CapabilityCategory.CRYPTO,
        "Hash creation via crypto.createHash",
        0.95,
    ),
    (
        re.compile(r"crypto\s*\.\s*createHmac\s*\("),
        CapabilityCategory.CRYPTO,
        "HMAC creation via crypto.createHmac",
        0.95,
    ),
    (
        re.compile(r"crypto\s*\.\s*createCipher(?:iv)?\s*\("),
        CapabilityCategory.CRYPTO,
        "Cipher creation via crypto.createCipher",
        0.95,
    ),
    # Database
    (
        re.compile(r"require\s*\(\s*['\"](?:mysql|mysql2)['\"]\s*\)"),
        CapabilityCategory.DATABASE,
        "Import of MySQL module",
        0.7,
    ),
    (
        re.compile(r"require\s*\(\s*['\"]pg['\"]\s*\)"),
        CapabilityCategory.DATABASE,
        "Import of PostgreSQL module",
        0.7,
    ),
    (
        re.compile(r"require\s*\(\s*['\"]mongodb['\"]\s*\)"),
        CapabilityCategory.DATABASE,
        "Import of MongoDB module",
        0.7,
    ),
    (
        re.compile(r"require\s*\(\s*['\"]redis['\"]\s*\)"),
        CapabilityCategory.DATABASE,
        "Import of Redis module",
        0.7,
    ),
    # Serialization
    (
        re.compile(r"JSON\s*\.\s*parse\s*\("),
        CapabilityCategory.SERIALIZATION,
        "JSON deserialization via JSON.parse",
        0.80,
    ),
    (
        re.compile(r"JSON\s*\.\s*stringify\s*\("),
        CapabilityCategory.SERIALIZATION,
        "JSON serialization via JSON.stringify",
        0.60,
    ),
]


class JavaScriptAnalyzer:
    """Analyzes JavaScript/TypeScript code to discover capabilities.

    Uses regex-based pattern matching to detect capability-signaling
    code patterns. While less precise than a full AST analysis, this
    approach is fast, requires no external dependencies, and covers
    the most critical capability categories.

    A future version may integrate tree-sitter for improved accuracy.

    Usage::

        analyzer = JavaScriptAnalyzer()
        capabilities = analyzer.analyze(source_code, source_file="app.js")
    """

    def analyze(
        self,
        code_string: str,
        *,
        source_file: str = "<string>",
    ) -> list[Capability]:
        """Analyze JavaScript/TypeScript code for capabilities.

        Args:
            code_string: The source code to analyze.
            source_file: File path for source locations.

        Returns:
            A list of ``Capability`` instances found in the code.
        """
        capabilities: list[Capability] = []
        seen: set[tuple[str, int]] = set()  # (category, line) dedup

        lines = code_string.splitlines()

        for pattern, category, description, confidence in _CALL_PATTERNS:
            for match in pattern.finditer(code_string):
                # Compute line number from match position
                line = code_string[: match.start()].count("\n") + 1

                # Deduplicate: same category on the same line
                key = (category.value, line)
                if key in seen:
                    continue
                seen.add(key)

                # Extract the matching text as evidence
                evidence = match.group(0)
                # Clean up: truncate if too long
                if len(evidence) > 80:
                    evidence = evidence[:77] + "..."

                location = SourceLocation(
                    file=source_file,
                    line=line,
                )

                capabilities.append(
                    Capability(
                        category=category,
                        description=description,
                        evidence=evidence,
                        location=location,
                        reachability=ReachabilityStatus.REACHABLE,
                        confidence=confidence,
                    )
                )

        return capabilities
