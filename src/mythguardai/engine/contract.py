"""Semantic contract extraction for MythGuardAI.

A *semantic contract* captures the declared intent of a code unit by
analyzing its name, docstring, type hints, decorators, and import
patterns. This module provides ``ContractExtractor``, which walks an
AST and produces ``SemanticContract`` instances for each named code
unit (function, class, or module).

The extraction is purely static and deterministic: the same source
code always yields the same contracts.
"""

from __future__ import annotations

import ast
import re
from typing import Any

from mythguardai.models import (
    IntentCategory,
    SemanticContract,
    SourceLocation,
)

# ---------------------------------------------------------------------------
# Intent inference heuristics
# ---------------------------------------------------------------------------

# Keywords in function/method names that signal intent
_NAME_INTENT_MAP: dict[str, IntentCategory] = {
    "read": IntentCategory.FILE_READ,
    "load": IntentCategory.FILE_READ,
    "open": IntentCategory.FILE_READ,
    "fetch": IntentCategory.NETWORK,
    "get": IntentCategory.FILE_READ,
    "parse": IntentCategory.PARSING,
    "write": IntentCategory.FILE_WRITE,
    "save": IntentCategory.FILE_WRITE,
    "store": IntentCategory.FILE_WRITE,
    "persist": IntentCategory.FILE_WRITE,
    "dump": IntentCategory.FILE_WRITE,
    "send": IntentCategory.NETWORK,
    "post": IntentCategory.NETWORK,
    "put": IntentCategory.NETWORK,
    "request": IntentCategory.NETWORK,
    "connect": IntentCategory.NETWORK,
    "download": IntentCategory.NETWORK,
    "upload": IntentCategory.NETWORK,
    "serve": IntentCategory.NETWORK,
    "listen": IntentCategory.NETWORK,
    "execute": IntentCategory.SUBPROCESS,
    "run": IntentCategory.SUBPROCESS,
    "spawn": IntentCategory.SUBPROCESS,
    "launch": IntentCategory.SUBPROCESS,
    "call": IntentCategory.SUBPROCESS,
    "invoke": IntentCategory.SUBPROCESS,
    "compute": IntentCategory.COMPUTATION,
    "calculate": IntentCategory.COMPUTATION,
    "process": IntentCategory.COMPUTATION,
    "transform": IntentCategory.COMPUTATION,
    "convert": IntentCategory.COMPUTATION,
    "encrypt": IntentCategory.CRYPTO,
    "decrypt": IntentCategory.CRYPTO,
    "hash": IntentCategory.CRYPTO,
    "sign": IntentCategory.CRYPTO,
    "verify": IntentCategory.CRYPTO,
    "serialize": IntentCategory.SERIALIZATION,
    "deserialize": IntentCategory.SERIALIZATION,
    "encode": IntentCategory.SERIALIZATION,
    "decode": IntentCategory.SERIALIZATION,
    "query": IntentCategory.DATABASE,
    "insert": IntentCategory.DATABASE,
    "update": IntentCategory.DATABASE,
    "delete": IntentCategory.DATABASE,
    "select": IntentCategory.DATABASE,
    "migrate": IntentCategory.DATABASE,
    "chmod": IntentCategory.PRIVILEGE,
    "chown": IntentCategory.PRIVILEGE,
    "elevate": IntentCategory.PRIVILEGE,
    "sudo": IntentCategory.PRIVILEGE,
    "escalate": IntentCategory.PRIVILEGE,
    "eval": IntentCategory.DYNAMIC_EXEC,
    "exec": IntentCategory.DYNAMIC_EXEC,
    "compile": IntentCategory.DYNAMIC_EXEC,
}

# Docstring keywords that signal intent
_DOCSTRING_INTENT_MAP: dict[str, IntentCategory] = {
    "read": IntentCategory.FILE_READ,
    "write": IntentCategory.FILE_WRITE,
    "network": IntentCategory.NETWORK,
    "http": IntentCategory.NETWORK,
    "request": IntentCategory.NETWORK,
    "socket": IntentCategory.NETWORK,
    "subprocess": IntentCategory.SUBPROCESS,
    "execute": IntentCategory.SUBPROCESS,
    "shell": IntentCategory.SUBPROCESS,
    "command": IntentCategory.SUBPROCESS,
    "privilege": IntentCategory.PRIVILEGE,
    "permission": IntentCategory.PRIVILEGE,
    "eval": IntentCategory.DYNAMIC_EXEC,
    "exec": IntentCategory.DYNAMIC_EXEC,
    "serialize": IntentCategory.SERIALIZATION,
    "deserialize": IntentCategory.SERIALIZATION,
    "encrypt": IntentCategory.CRYPTO,
    "decrypt": IntentCategory.CRYPTO,
    "database": IntentCategory.DATABASE,
    "sql": IntentCategory.DATABASE,
    "query": IntentCategory.DATABASE,
    "environment": IntentCategory.ENVIRONMENT,
    "env": IntentCategory.ENVIRONMENT,
    "temp": IntentCategory.FILE_WRITE,
    "cache": IntentCategory.FILE_WRITE,
}

# Type annotations that signal intent
_TYPE_INTENT_MAP: dict[str, IntentCategory] = {
    "Path": IntentCategory.FILE_READ,
    "FilePath": IntentCategory.FILE_READ,
    "File": IntentCategory.FILE_READ,
    "IO": IntentCategory.FILE_READ,
    "TextIO": IntentCategory.FILE_READ,
    "BinaryIO": IntentCategory.FILE_READ,
    "HttpResponse": IntentCategory.NETWORK,
    "Request": IntentCategory.NETWORK,
    "Response": IntentCategory.NETWORK,
    "Socket": IntentCategory.NETWORK,
    "Connection": IntentCategory.NETWORK,
    "CompletedProcess": IntentCategory.SUBPROCESS,
    "Cursor": IntentCategory.DATABASE,
    "Connection": IntentCategory.DATABASE,
    "Session": IntentCategory.DATABASE,
}

# Decorators that signal intent
_DECORATOR_INTENT_MAP: dict[str, IntentCategory] = {
    "app.route": IntentCategory.NETWORK,
    "route": IntentCategory.NETWORK,
    "get": IntentCategory.NETWORK,
    "post": IntentCategory.NETWORK,
    "put": IntentCategory.NETWORK,
    "delete": IntentCategory.NETWORK,
    "patch": IntentCategory.NETWORK,
    "api_view": IntentCategory.NETWORK,
    "require_admin": IntentCategory.PRIVILEGE,
    "require_permission": IntentCategory.PRIVILEGE,
    "login_required": IntentCategory.PRIVILEGE,
    "cached": IntentCategory.FILE_WRITE,
    "task": IntentCategory.SUBPROCESS,
    "celery": IntentCategory.SUBPROCESS,
    "background": IntentCategory.SUBPROCESS,
}


class ContractExtractor:
    """Extracts semantic contracts from Python AST nodes.

    The extractor infers declared intent from multiple signals:
    function/class names, docstrings, type hints, and decorators.
    Each signal contributes to a confidence-weighted set of
    ``IntentCategory`` values.
    """

    def __init__(self) -> None:
        self._source_file: str = "<module>"

    def extract_from_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> SemanticContract:
        """Extract a semantic contract from a function definition.

        Args:
            node: The AST node for the function.

        Returns:
            A ``SemanticContract`` capturing the declared intent.
        """
        name = node.name
        intents = self._infer_intents_from_name(name)
        docstring = ast.get_docstring(node) or None
        type_annotations = self._extract_type_annotations(node)
        decorators = self._extract_decorators(node)

        # Layer on additional intent from docstring, types, decorators
        doc_intents = self._infer_intents_from_docstring(docstring) if docstring else set()
        type_intents = self._infer_intents_from_types(type_annotations)
        dec_intents = self._infer_intents_from_decorators(decorators)

        all_intents = intents | doc_intents | type_intents | dec_intents
        if not all_intents:
            all_intents = {IntentCategory.COMPUTATION}

        # Confidence decreases as we rely on weaker signals
        confidence = 1.0
        if not intents and doc_intents:
            confidence = 0.8
        if not intents and not doc_intents:
            confidence = 0.5

        location = SourceLocation(
            file=self._source_file,
            line=node.lineno,
            col=node.col_offset,
            end_line=getattr(node, "end_lineno", 0) or 0,
            end_col=getattr(node, "end_col_offset", -1) or -1,
        )

        return SemanticContract(
            name=name,
            source=self._source_file,
            declared_intents=all_intents,
            docstring=docstring,
            type_annotations=type_annotations,
            decorators=decorators,
            location=location,
            confidence=confidence,
        )

    def extract_from_class(self, node: ast.ClassDef) -> SemanticContract:
        """Extract a semantic contract from a class definition.

        The class-level contract aggregates intent from the class name,
        base classes, and the combined contracts of its methods.

        Args:
            node: The AST node for the class.

        Returns:
            A ``SemanticContract`` capturing the declared intent.
        """
        name = node.name
        intents = self._infer_intents_from_name(name)
        docstring = ast.get_docstring(node) or None
        decorators = self._extract_decorators(node)
        bases = [self._node_to_name(base) for base in node.bases]

        # Check base class names for intent signals
        for base in bases:
            for keyword, category in _NAME_INTENT_MAP.items():
                if keyword in base.lower():
                    intents.add(category)

        dec_intents = self._infer_intents_from_decorators(decorators)
        doc_intents = self._infer_intents_from_docstring(docstring) if docstring else set()

        # Collect type annotations from class body
        type_annotations: dict[str, str] = {}
        for item in node.body:
            if isinstance(item, ast.AnnAssign) and item.annotation:
                ann_name = self._node_to_name(item.annotation)
                var_name = ""
                if isinstance(item.target, ast.Name):
                    var_name = item.target.id
                if var_name:
                    type_annotations[var_name] = ann_name

        type_intents = self._infer_intents_from_types(type_annotations)

        all_intents = intents | dec_intents | doc_intents | type_intents
        if not all_intents:
            all_intents = {IntentCategory.COMPUTATION}

        confidence = 0.9 if intents else 0.6

        location = SourceLocation(
            file=self._source_file,
            line=node.lineno,
            col=node.col_offset,
            end_line=getattr(node, "end_lineno", 0) or 0,
            end_col=getattr(node, "end_col_offset", -1) or -1,
        )

        return SemanticContract(
            name=name,
            source=self._source_file,
            declared_intents=all_intents,
            docstring=docstring,
            type_annotations=type_annotations,
            decorators=decorators,
            location=location,
            confidence=confidence,
            metadata={"bases": bases},
        )

    def extract_from_module(self, tree: ast.Module) -> SemanticContract:
        """Extract a module-level semantic contract.

        Aggregates intent from module-level docstrings, imports,
        and top-level function/class contracts.

        Args:
            tree: The AST root node for the module.

        Returns:
            A ``SemanticContract`` capturing the declared intent.
        """
        intents: set[IntentCategory] = set()
        docstring = ast.get_docstring(tree) or None

        if docstring:
            intents |= self._infer_intents_from_docstring(docstring)

        # Scan imports for intent signals
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                module_name = self._get_import_module(node)
                if module_name:
                    intents |= self._infer_intents_from_imports(module_name)

        if not intents:
            intents = {IntentCategory.COMPUTATION}

        location = SourceLocation(file=self._source_file)

        return SemanticContract(
            name=self._source_file,
            source=self._source_file,
            declared_intents=intents,
            docstring=docstring,
            confidence=0.7 if intents else 0.4,
            location=location,
        )

    def set_source_file(self, source_file: str) -> None:
        """Set the source file path for subsequent extractions.

        Args:
            source_file: Path to the source file being analyzed.
        """
        self._source_file = source_file

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _infer_intents_from_name(self, name: str) -> set[IntentCategory]:
        """Infer intent categories from a function or class name."""
        intents: set[IntentCategory] = set()
        name_lower = name.lower()

        # Split on common separators and check each part
        parts = re.split(r"[_\-]", name_lower)
        for part in parts:
            for keyword, category in _NAME_INTENT_MAP.items():
                if keyword == part or keyword in part:
                    intents.add(category)

        return intents

    def _infer_intents_from_docstring(
        self, docstring: str
    ) -> set[IntentCategory]:
        """Infer intent categories from a docstring."""
        intents: set[IntentCategory] = set()
        doc_lower = docstring.lower()

        for keyword, category in _DOCSTRING_INTENT_MAP.items():
            if keyword in doc_lower:
                intents.add(category)

        return intents

    def _infer_intents_from_types(
        self, type_annotations: dict[str, str]
    ) -> set[IntentCategory]:
        """Infer intent categories from type annotations."""
        intents: set[IntentCategory] = set()
        for ann_type in type_annotations.values():
            for type_hint, category in _TYPE_INTENT_MAP.items():
                if type_hint.lower() in ann_type.lower():
                    intents.add(category)
        return intents

    def _infer_intents_from_decorators(
        self, decorators: list[str]
    ) -> set[IntentCategory]:
        """Infer intent categories from decorators."""
        intents: set[IntentCategory] = set()
        for dec in decorators:
            dec_lower = dec.lower()
            for pattern, category in _DECORATOR_INTENT_MAP.items():
                if pattern in dec_lower:
                    intents.add(category)
        return intents

    def _infer_intents_from_imports(self, module_name: str) -> set[IntentCategory]:
        """Infer intent from imported module names."""
        intents: set[IntentCategory] = set()
        module_lower = module_name.lower()

        import_signals: dict[str, IntentCategory] = {
            "subprocess": IntentCategory.SUBPROCESS,
            "os": IntentCategory.ENVIRONMENT,
            "sys": IntentCategory.ENVIRONMENT,
            "shutil": IntentCategory.FILE_WRITE,
            "pathlib": IntentCategory.FILE_READ,
            "socket": IntentCategory.NETWORK,
            "http": IntentCategory.NETWORK,
            "urllib": IntentCategory.NETWORK,
            "requests": IntentCategory.NETWORK,
            "aiohttp": IntentCategory.NETWORK,
            "paramiko": IntentCategory.NETWORK,
            "ftplib": IntentCategory.NETWORK,
            "smtplib": IntentCategory.NETWORK,
            "sqlite": IntentCategory.DATABASE,
            "psycopg": IntentCategory.DATABASE,
            "mysql": IntentCategory.DATABASE,
            "pymongo": IntentCategory.DATABASE,
            "redis": IntentCategory.DATABASE,
            "sqlalchemy": IntentCategory.DATABASE,
            "crypto": IntentCategory.CRYPTO,
            "hashlib": IntentCategory.CRYPTO,
            "hmac": IntentCategory.CRYPTO,
            "ssl": IntentCategory.CRYPTO,
            "pickle": IntentCategory.SERIALIZATION,
            "json": IntentCategory.SERIALIZATION,
            "yaml": IntentCategory.SERIALIZATION,
            "xml": IntentCategory.PARSING,
            "csv": IntentCategory.PARSING,
            "configparser": IntentCategory.PARSING,
            "tempfile": IntentCategory.FILE_WRITE,
            "io": IntentCategory.FILE_READ,
        }

        for signal, category in import_signals.items():
            if signal in module_lower:
                intents.add(category)

        return intents

    def _extract_type_annotations(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> dict[str, str]:
        """Extract type annotations from a function definition."""
        annotations: dict[str, str] = {}

        # Return annotation
        if node.returns:
            annotations["return"] = self._node_to_name(node.returns)

        # Argument annotations
        for arg in node.args.args:
            if arg.annotation:
                annotations[arg.arg] = self._node_to_name(arg.annotation)

        return annotations

    def _extract_decorators(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef
    ) -> list[str]:
        """Extract decorator names from a definition node."""
        decorators: list[str] = []
        for dec in node.decorator_list:
            decorators.append(self._node_to_name(dec))
        return decorators

    def _node_to_name(self, node: ast.AST) -> str:
        """Convert an AST node to its string representation.

        Handles Name, Attribute, Subscript, and Constant nodes.
        """
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return f"{self._node_to_name(node.value)}.{node.attr}"
        if isinstance(node, ast.Subscript):
            return f"{self._node_to_name(node.value)}[...]"
        if isinstance(node, ast.Constant):
            return repr(node.value)
        if isinstance(node, ast.Call):
            return self._node_to_name(node.func)
        if isinstance(node, ast.Starred):
            return f"*{self._node_to_name(node.value)}"
        return "..."

    def _get_import_module(self, node: ast.Import | ast.ImportFrom) -> str:
        """Get the module name from an import node."""
        if isinstance(node, ast.ImportFrom) and node.module:
            return node.module
        if isinstance(node, ast.Import):
            # Use the first imported name's module
            if node.names:
                return node.names[0].name
        return ""
