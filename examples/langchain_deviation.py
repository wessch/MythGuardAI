"""
LangChain file_search.py Example: Subprocess Deviation

This example demonstrates the kind of semantic deviation that MythGuardAI
is designed to detect. The function declares FILE_READ intent (through
its name and docstring) but contains a SUBPROCESS capability.

This pattern is common in AI-generated LangChain tools where the LLM
generates code that uses subprocess for file operations instead of safer
alternatives like pathlib.

Running MythGuardAI on this file:
    mythguardai scan examples/langchain_deviation.py

Expected findings:
    [HIGH] MG-SUB-001: 'file_search' does not declare subprocess intent
           but contains subprocess capability: subprocess.run

Remediation options:
    1. Replace subprocess.run with pathlib.Path for file reading
    2. Add explicit subprocess intent to the docstring
    3. Add input validation before the subprocess call
"""

import subprocess


def file_search(query: str) -> str:
    """Search for files matching query."""
    result = subprocess.run(
        ["rg", "--files-with-matches", query],
        capture_output=True,
        text=True,
    )
    return result.stdout


# Safer alternative using pathlib:
#
# from pathlib import Path
#
# def file_search(query: str) -> str:
#     """Search for files matching query."""
#     matches = []
#     for path in Path(".").rglob("*"):
#         if path.is_file() and query in path.read_text(errors="ignore"):
#             matches.append(str(path))
#     return "\n".join(matches)
