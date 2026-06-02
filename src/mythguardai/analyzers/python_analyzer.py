"""Python AST analyzer for MythGuardAI.

Discovers capabilities in Python source code by walking the AST and
matching function calls, import patterns, and attribute accesses to
known capability categories.

Detection coverage:
- subprocess calls (subprocess.run, subprocess.Popen, os.system, etc.)
- file I/O (open, pathlib, os.listdir, etc.)
- network access (socket, requests, urllib, http, etc.)
- privilege operations (os.chmod, os.chown, os.setuid, etc.)
- dynamic execution (eval, exec, compile)
- environment access (os.environ, os.getenv, etc.)
- import patterns for sensitive modules
- temporary file creation
- signal handling
- module import patterns
"""

from __future__ import annotations

import ast
from typing import Any

from mythguardai.models import (
    Capability,
    CapabilityCategory,
    ReachabilityStatus,
    SourceLocation,
)


# ---------------------------------------------------------------------------
# Capability signature definitions
# ---------------------------------------------------------------------------

# Each entry maps a dotted call path to (category, description).
_CALL_SIGNATURES: dict[str, tuple[CapabilityCategory, str]] = {
    # Subprocess execution
    "subprocess.run": (CapabilityCategory.SUBPROCESS, "Subprocess execution via subprocess.run"),
    "subprocess.Popen": (CapabilityCategory.SUBPROCESS, "Subprocess execution via subprocess.Popen"),
    "subprocess.call": (CapabilityCategory.SUBPROCESS, "Subprocess execution via subprocess.call"),
    "subprocess.check_call": (CapabilityCategory.SUBPROCESS, "Subprocess execution via subprocess.check_call"),
    "subprocess.check_output": (CapabilityCategory.SUBPROCESS, "Subprocess execution via subprocess.check_output"),
    "os.system": (CapabilityCategory.SUBPROCESS, "Shell command execution via os.system"),
    "os.popen": (CapabilityCategory.SUBPROCESS, "Shell command execution via os.popen"),
    "os.spawnl": (CapabilityCategory.SUBPROCESS, "Process spawning via os.spawnl"),
    "os.spawnle": (CapabilityCategory.SUBPROCESS, "Process spawning via os.spawnle"),
    "os.spawnlp": (CapabilityCategory.SUBPROCESS, "Process spawning via os.spawnlp"),
    "os.spawnv": (CapabilityCategory.SUBPROCESS, "Process spawning via os.spawnv"),
    "os.spawnve": (CapabilityCategory.SUBPROCESS, "Process spawning via os.spawnve"),
    # File read
    "open": (CapabilityCategory.FILE_READ, "File open operation"),
    "pathlib.Path.read_text": (CapabilityCategory.FILE_READ, "File read via pathlib"),
    "pathlib.Path.read_bytes": (CapabilityCategory.FILE_READ, "File read via pathlib"),
    "pathlib.Path.open": (CapabilityCategory.FILE_READ, "File open via pathlib"),
    "os.listdir": (CapabilityCategory.FILE_READ, "Directory listing via os.listdir"),
    "os.scandir": (CapabilityCategory.FILE_READ, "Directory scanning via os.scandir"),
    "os.read": (CapabilityCategory.FILE_READ, "File read via os.read"),
    "shutil.copy": (CapabilityCategory.FILE_READ, "File copy via shutil"),
    "shutil.copy2": (CapabilityCategory.FILE_READ, "File copy via shutil"),
    # File write
    "pathlib.Path.write_text": (CapabilityCategory.FILE_WRITE, "File write via pathlib"),
    "pathlib.Path.write_bytes": (CapabilityCategory.FILE_WRITE, "File write via pathlib"),
    "os.mkdir": (CapabilityCategory.FILE_WRITE, "Directory creation via os.mkdir"),
    "os.makedirs": (CapabilityCategory.FILE_WRITE, "Directory creation via os.makedirs"),
    "os.rename": (CapabilityCategory.FILE_WRITE, "File rename via os.rename"),
    "os.remove": (CapabilityCategory.FILE_WRITE, "File deletion via os.remove"),
    "os.unlink": (CapabilityCategory.FILE_WRITE, "File deletion via os.unlink"),
    "os.rmdir": (CapabilityCategory.FILE_WRITE, "Directory removal via os.rmdir"),
    "shutil.rmtree": (CapabilityCategory.FILE_WRITE, "Directory tree removal via shutil"),
    "shutil.move": (CapabilityCategory.FILE_WRITE, "File move via shutil"),
    "shutil.copytree": (CapabilityCategory.FILE_WRITE, "Directory tree copy via shutil"),
    # Network client
    "socket.socket": (CapabilityCategory.NETWORK_CLIENT, "Socket creation"),
    "requests.get": (CapabilityCategory.NETWORK_CLIENT, "HTTP GET request via requests"),
    "requests.post": (CapabilityCategory.NETWORK_CLIENT, "HTTP POST request via requests"),
    "requests.put": (CapabilityCategory.NETWORK_CLIENT, "HTTP PUT request via requests"),
    "requests.delete": (CapabilityCategory.NETWORK_CLIENT, "HTTP DELETE request via requests"),
    "requests.patch": (CapabilityCategory.NETWORK_CLIENT, "HTTP PATCH request via requests"),
    "requests.head": (CapabilityCategory.NETWORK_CLIENT, "HTTP HEAD request via requests"),
    "urllib.request.urlopen": (CapabilityCategory.NETWORK_CLIENT, "URL open via urllib"),
    "urllib.request.urlretrieve": (CapabilityCategory.NETWORK_CLIENT, "URL retrieval via urllib"),
    "http.client.HTTPConnection": (CapabilityCategory.NETWORK_CLIENT, "HTTP connection via http.client"),
    "http.client.HTTPSConnection": (CapabilityCategory.NETWORK_CLIENT, "HTTPS connection via http.client"),
    "aiohttp.ClientSession": (CapabilityCategory.NETWORK_CLIENT, "Async HTTP client via aiohttp"),
    "paramiko.SSHClient": (CapabilityCategory.NETWORK_CLIENT, "SSH client via paramiko"),
    # Network server
    "socketserver.TCPServer": (CapabilityCategory.NETWORK_SERVER, "TCP server via socketserver"),
    "socketserver.UDPServer": (CapabilityCategory.NETWORK_SERVER, "UDP server via socketserver"),
    "http.server.HTTPServer": (CapabilityCategory.NETWORK_SERVER, "HTTP server"),
    "flask.Flask.run": (CapabilityCategory.NETWORK_SERVER, "Flask development server"),
    # Privilege escalation
    "os.chmod": (CapabilityCategory.PRIVILEGE_ESCALATION, "File permission change via os.chmod"),
    "os.chown": (CapabilityCategory.PRIVILEGE_ESCALATION, "File ownership change via os.chown"),
    "os.setuid": (CapabilityCategory.PRIVILEGE_ESCALATION, "User ID change via os.setuid"),
    "os.setgid": (CapabilityCategory.PRIVILEGE_ESCALATION, "Group ID change via os.setgid"),
    "os.seteuid": (CapabilityCategory.PRIVILEGE_ESCALATION, "Effective user ID change via os.seteuid"),
    "os.setegid": (CapabilityCategory.PRIVILEGE_ESCALATION, "Effective group ID change via os.setegid"),
    "os.setreuid": (CapabilityCategory.PRIVILEGE_ESCALATION, "Real/effective user ID change via os.setreuid"),
    "os.setregid": (CapabilityCategory.PRIVILEGE_ESCALATION, "Real/effective group ID change via os.setregid"),
    # Dynamic execution
    "eval": (CapabilityCategory.DYNAMIC_EXEC, "Dynamic code evaluation via eval()"),
    "exec": (CapabilityCategory.DYNAMIC_EXEC, "Dynamic code execution via exec()"),
    "compile": (CapabilityCategory.DYNAMIC_EXEC, "Code compilation via compile()"),
    # Environment read
    "os.getenv": (CapabilityCategory.ENVIRONMENT_READ, "Environment variable read via os.getenv"),
    # Environment write
    "os.putenv": (CapabilityCategory.ENVIRONMENT_WRITE, "Environment variable write via os.putenv"),
    # Temporary files
    "tempfile.mktemp": (CapabilityCategory.TEMP_FILE, "Temporary file creation via tempfile.mktemp"),
    "tempfile.mkstemp": (CapabilityCategory.TEMP_FILE, "Temporary file creation via tempfile.mkstemp"),
    "tempfile.mkdtemp": (CapabilityCategory.TEMP_FILE, "Temporary directory creation via tempfile.mkdtemp"),
    "tempfile.NamedTemporaryFile": (CapabilityCategory.TEMP_FILE, "Named temporary file via tempfile"),
    # Signal handling
    "signal.signal": (CapabilityCategory.SIGNAL_HANDLING, "Signal handler registration via signal.signal"),
    # Serialization
    "pickle.load": (CapabilityCategory.SERIALIZATION, "Deserialization via pickle.load"),
    "pickle.loads": (CapabilityCategory.SERIALIZATION, "Deserialization via pickle.loads"),
    "pickle.dump": (CapabilityCategory.SERIALIZATION, "Serialization via pickle.dump"),
    "pickle.dumps": (CapabilityCategory.SERIALIZATION, "Serialization via pickle.dumps"),
    # Crypto
    "hashlib.sha256": (CapabilityCategory.CRYPTO, "SHA-256 hashing via hashlib"),
    "hashlib.sha512": (CapabilityCategory.CRYPTO, "SHA-512 hashing via hashlib"),
    "hashlib.md5": (CapabilityCategory.CRYPTO, "MD5 hashing via hashlib"),
    "hmac.new": (CapabilityCategory.CRYPTO, "HMAC creation via hmac"),
}

# Import patterns that signal capabilities
_IMPORT_CAPABILITY_MAP: dict[str, tuple[CapabilityCategory, str]] = {
    "subprocess": (CapabilityCategory.SUBPROCESS, "Import of subprocess module"),
    "os": (CapabilityCategory.ENVIRONMENT_READ, "Import of os module"),
    "socket": (CapabilityCategory.NETWORK_CLIENT, "Import of socket module"),
    "requests": (CapabilityCategory.NETWORK_CLIENT, "Import of requests module"),
    "urllib.request": (CapabilityCategory.NETWORK_CLIENT, "Import of urllib.request module"),
    "http.client": (CapabilityCategory.NETWORK_CLIENT, "Import of http.client module"),
    "aiohttp": (CapabilityCategory.NETWORK_CLIENT, "Import of aiohttp module"),
    "paramiko": (CapabilityCategory.NETWORK_CLIENT, "Import of paramiko module"),
    "ftplib": (CapabilityCategory.NETWORK_CLIENT, "Import of ftplib module"),
    "smtplib": (CapabilityCategory.NETWORK_CLIENT, "Import of smtplib module"),
    "ssl": (CapabilityCategory.CRYPTO, "Import of ssl module"),
    "hashlib": (CapabilityCategory.CRYPTO, "Import of hashlib module"),
    "hmac": (CapabilityCategory.CRYPTO, "Import of hmac module"),
    "pickle": (CapabilityCategory.SERIALIZATION, "Import of pickle module"),
    "shelve": (CapabilityCategory.SERIALIZATION, "Import of shelve module"),
    "signal": (CapabilityCategory.SIGNAL_HANDLING, "Import of signal module"),
    "tempfile": (CapabilityCategory.TEMP_FILE, "Import of tempfile module"),
    "shutil": (CapabilityCategory.FILE_WRITE, "Import of shutil module"),
    "sqlite3": (CapabilityCategory.DATABASE, "Import of sqlite3 module"),
    "psycopg2": (CapabilityCategory.DATABASE, "Import of psycopg2 module"),
    "pymysql": (CapabilityCategory.DATABASE, "Import of pymysql module"),
    "pymongo": (CapabilityCategory.DATABASE, "Import of pymongo module"),
    "redis": (CapabilityCategory.DATABASE, "Import of redis module"),
}

# Attribute accesses that signal capabilities
_ATTR_CAPABILITY_MAP: dict[str, tuple[CapabilityCategory, str]] = {
    "os.environ": (CapabilityCategory.ENVIRONMENT_READ, "Environment variable access via os.environ"),
}


class PythonAnalyzer:
    """Analyzes Python AST to discover capabilities.

    Walks the AST looking for function calls, import statements,
    and attribute accesses that indicate specific capabilities.
    Each discovered capability is returned as a ``Capability``
    instance with source location information.

    Usage::

        analyzer = PythonAnalyzer()
        tree = ast.parse(source_code)
        capabilities = analyzer.analyze(tree, source_file="example.py")
    """

    def __init__(self) -> None:
        self._source_file: str = "<string>"
        self._import_aliases: dict[str, str] = {}

    def analyze(
        self,
        tree: ast.Module,
        *,
        source_file: str = "<string>",
    ) -> list[Capability]:
        """Analyze a Python AST and return discovered capabilities.

        Args:
            tree: The parsed AST module node.
            source_file: File path for source locations.

        Returns:
            A list of ``Capability`` instances found in the code.
        """
        self._source_file = source_file
        self._import_aliases = {}
        capabilities: list[Capability] = []

        # First pass: collect import aliases
        self._collect_import_aliases(tree)

        # Second pass: walk the AST for capabilities
        for node in ast.walk(tree):
            caps = self._visit_node(node)
            capabilities.extend(caps)

        return capabilities

    # ------------------------------------------------------------------
    # Node visitors
    # ------------------------------------------------------------------

    def _visit_node(self, node: ast.AST) -> list[Capability]:
        """Dispatch to the appropriate visitor based on node type."""
        if isinstance(node, ast.Call):
            return self._visit_call(node)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            return self._visit_import(node)
        elif isinstance(node, ast.Attribute):
            return self._visit_attribute(node)
        elif isinstance(node, ast.Expr):
            # Check for os.environ access patterns
            if isinstance(node.value, ast.Call):
                return self._visit_call(node.value)
        return []

    def _visit_call(self, node: ast.Call) -> list[Capability]:
        """Analyze a function call node for known capability signatures."""
        call_path = self._resolve_call_path(node)
        if not call_path:
            return []

        capabilities: list[Capability] = []

        # Check direct call signatures
        category, description = self._match_call_signature(call_path)
        if category is not None:
            cap = self._make_capability(
                category=category,
                description=description,
                evidence=call_path,
                node=node,
            )
            capabilities.append(cap)

        # Special handling: open() with mode 'w', 'a', 'x' = FILE_WRITE
        if call_path == "open":
            write_cap = self._check_open_write_mode(node)
            if write_cap:
                capabilities.append(write_cap)

        return capabilities

    def _visit_import(self, node: ast.Import | ast.ImportFrom) -> list[Capability]:
        """Analyze an import statement for capability-signaling imports."""
        capabilities: list[Capability] = []

        if isinstance(node, ast.ImportFrom) and node.module:
            module_name = node.module
        elif isinstance(node, ast.Import) and node.names:
            module_name = node.names[0].name
        else:
            return []

        # Check partial matches (e.g. "urllib.request" matches "urllib.request")
        for pattern, (category, description) in _IMPORT_CAPABILITY_MAP.items():
            if module_name == pattern or module_name.startswith(pattern + "."):
                cap = self._make_capability(
                    category=category,
                    description=description,
                    evidence=f"import {module_name}",
                    node=node,
                    confidence=0.6,
                )
                capabilities.append(cap)
                break

        return capabilities

    def _visit_attribute(self, node: ast.Attribute) -> list[Capability]:
        """Analyze an attribute access for capability signals."""
        attr_path = self._resolve_attribute_path(node)
        if not attr_path:
            return []

        if attr_path in _ATTR_CAPABILITY_MAP:
            category, description = _ATTR_CAPABILITY_MAP[attr_path]
            cap = self._make_capability(
                category=category,
                description=description,
                evidence=attr_path,
                node=node,
                confidence=0.7,
            )
            return [cap]

        return []

    # ------------------------------------------------------------------
    # Resolution helpers
    # ------------------------------------------------------------------

    def _resolve_call_path(self, node: ast.Call) -> str:
        """Resolve a Call node to its dotted call path string.

        Examples:
            ``subprocess.run(...)`` -> ``"subprocess.run"``
            ``open(...)`` -> ``"open"``
            ``sp.run(...)`` (where ``import subprocess as sp``) -> ``"subprocess.run"``
        """
        func = node.func
        return self._resolve_dotted_name(func)

    def _resolve_dotted_name(self, node: ast.AST) -> str:
        """Resolve an AST node to its dotted name, resolving aliases."""
        if isinstance(node, ast.Name):
            # Check if this is an import alias
            name = node.id
            if name in self._import_aliases:
                return self._import_aliases[name]
            return name

        if isinstance(node, ast.Attribute):
            value = self._resolve_dotted_name(node.value)
            if value:
                return f"{value}.{node.attr}"
            return node.attr

        return ""

    def _resolve_attribute_path(self, node: ast.Attribute) -> str:
        """Resolve an Attribute node to its dotted path."""
        parts: list[str] = []
        current: ast.AST = node

        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value

        if isinstance(current, ast.Name):
            parts.append(current.id)

        parts.reverse()
        return ".".join(parts)

    def _collect_import_aliases(self, tree: ast.Module) -> None:
        """Collect import aliases from the AST.

        Handles patterns like ``import subprocess as sp`` or
        ``from subprocess import run``.
        """
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.asname:
                        self._import_aliases[alias.asname] = alias.name
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for alias in node.names:
                    full_path = f"{module}.{alias.name}" if module else alias.name
                    effective_as = alias.asname or alias.name
                    self._import_aliases[effective_as] = full_path

    def _match_call_signature(
        self, call_path: str
    ) -> tuple[CapabilityCategory | None, str]:
        """Match a call path against known capability signatures.

        Returns (category, description) or (None, "") if no match.
        """
        # Direct match
        if call_path in _CALL_SIGNATURES:
            return _CALL_SIGNATURES[call_path]

        # Partial match: check if the call path starts with a known prefix
        for signature, (category, description) in _CALL_SIGNATURES.items():
            if call_path.startswith(signature + "."):
                return category, description

        return None, ""

    def _check_open_write_mode(self, node: ast.Call) -> Capability | None:
        """Check if an ``open()`` call opens a file for writing.

        The default mode is ``'r'``, so only explicit write modes
        (``'w'``, ``'a'``, ``'x'``, ``'wb'``, etc.) produce a
        FILE_WRITE capability.
        """
        if len(node.args) >= 2:
            mode_arg = node.args[1]
            if isinstance(mode_arg, ast.Constant) and isinstance(mode_arg.value, str):
                mode = mode_arg.value
                if any(c in mode for c in "wax"):
                    return self._make_capability(
                        category=CapabilityCategory.FILE_WRITE,
                        description=f"File open with write mode '{mode}'",
                        evidence=f"open(..., '{mode}')",
                        node=node,
                    )

        # Check keyword arguments
        for kw in node.keywords:
            if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                mode = kw.value.value
                if isinstance(mode, str) and any(c in mode for c in "wax"):
                    return self._make_capability(
                        category=CapabilityCategory.FILE_WRITE,
                        description=f"File open with write mode '{mode}'",
                        evidence=f"open(mode='{mode}')",
                        node=node,
                    )

        return None

    def _make_capability(
        self,
        category: CapabilityCategory,
        description: str,
        evidence: str,
        node: ast.AST,
        confidence: float = 0.9,
    ) -> Capability:
        """Create a Capability from an AST node."""
        location = SourceLocation(
            file=self._source_file,
            line=getattr(node, "lineno", 0),
            col=getattr(node, "col_offset", -1),
            end_line=getattr(node, "end_lineno", 0) or 0,
            end_col=getattr(node, "end_col_offset", -1) or -1,
        )

        return Capability(
            category=category,
            description=description,
            evidence=evidence,
            location=location,
            reachability=ReachabilityStatus.REACHABLE,
            confidence=confidence,
        )
