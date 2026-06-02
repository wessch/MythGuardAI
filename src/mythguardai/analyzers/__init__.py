"""MythGuardAI language analyzers.

Each analyzer discovers capabilities in source code for a specific
language and returns them as ``Capability`` instances.
"""

from mythguardai.analyzers.python_analyzer import PythonAnalyzer

__all__ = ["PythonAnalyzer"]

# Conditionally export the JavaScript analyzer
try:
    from mythguardai.analyzers.javascript_analyzer import JavaScriptAnalyzer

    __all__.append("JavaScriptAnalyzer")
except ImportError:  # pragma: no cover
    pass
