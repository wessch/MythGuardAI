"""Tests for the MythGuardScanner.

Covers: scan_code with known deviations, scan_file integration,
empty code handling, multi-function scanning, and the LangChain
file_search.py example.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from mythguardai.engine.scanner import MythGuardScanner
from mythguardai.exceptions import ScanError
from mythguardai.models import DeviationSeverity


class TestScanCode:
    """Tests for scan_code method."""

    def test_detects_subprocess_deviation(self, scanner: MythGuardScanner) -> None:
        code = '''
import subprocess

def read_config(path: str) -> str:
    """Read configuration from a file."""
    result = subprocess.run(["cat", path], capture_output=True, text=True)
    return result.stdout
'''
        result = scanner.scan_code(code, "python", source_file="config.py")
        assert result.has_deviations
        rule_ids = {d.rule_id for d in result.deviations}
        assert "MG-SUB-001" in rule_ids

    def test_detects_file_write_deviation(self, scanner: MythGuardScanner) -> None:
        code = '''
def read_data(path: str) -> str:
    """Read data from a file."""
    with open(path) as f:
        return f.read()
    with open("output.txt", "w") as out:
        out.write("log")
'''
        result = scanner.scan_code(code, "python", source_file="reader.py")
        # There should be file write capability in a read-intent function
        assert result.has_deviations

    def test_detects_network_deviation(self, scanner: MythGuardScanner) -> None:
        code = '''
import requests

def display_data(data: str) -> str:
    """Display the data for review."""
    response = requests.get("https://example.com/api")
    return response.text
'''
        result = scanner.scan_code(code, "python", source_file="viewer.py")
        assert result.has_deviations
        rule_ids = {d.rule_id for d in result.deviations}
        assert "MG-NET-001" in rule_ids

    def test_no_deviation_in_aligned_code(self, scanner: MythGuardScanner) -> None:
        code = '''
def add_numbers(a: int, b: int) -> int:
    """Add two numbers together."""
    return a + b
'''
        result = scanner.scan_code(code, "python", source_file="math.py")
        # Clean computation function should have no high-risk deviations
        high_risk = [d for d in result.deviations if d.severity >= DeviationSeverity.HIGH]
        assert len(high_risk) == 0


class TestScanFile:
    """Tests for scan_file integration."""

    def test_scan_file_with_subprocess_code(self, scanner: MythGuardScanner, tmp_dir: Path) -> None:
        code = '''
import subprocess

def read_config(path: str) -> str:
    """Read configuration from a file."""
    result = subprocess.run(["cat", path], capture_output=True, text=True)
    return result.stdout
'''
        file_path = tmp_dir / "subprocess_example.py"
        file_path.write_text(code, encoding="utf-8")
        result = scanner.scan_file(file_path)
        assert result.target == str(file_path)
        assert result.has_deviations
        rule_ids = {d.rule_id for d in result.deviations}
        assert "MG-SUB-001" in rule_ids

    def test_scan_file_not_found_raises(self, scanner: MythGuardScanner) -> None:
        with pytest.raises(ScanError):
            scanner.scan_file("/nonexistent/file.py")

    def test_scan_file_is_directory_raises(self, scanner: MythGuardScanner, tmp_dir: Path) -> None:
        with pytest.raises(ScanError):
            scanner.scan_file(tmp_dir)

    def test_scan_file_unsupported_extension_raises(self, scanner: MythGuardScanner, tmp_dir: Path) -> None:
        file_path = tmp_dir / "data.csv"
        file_path.write_text("a,b,c\n1,2,3", encoding="utf-8")
        with pytest.raises(ScanError):
            scanner.scan_file(file_path)


class TestEmptyCodeHandling:
    """Tests for empty code handling."""

    def test_empty_code_no_crash(self, scanner: MythGuardScanner) -> None:
        result = scanner.scan_code("", "python", source_file="empty.py")
        assert not result.has_deviations

    def test_whitespace_only_code(self, scanner: MythGuardScanner) -> None:
        result = scanner.scan_code("   \n\n   ", "python", source_file="spaces.py")
        assert not result.has_deviations

    def test_syntax_error_raises(self, scanner: MythGuardScanner) -> None:
        with pytest.raises(ScanError):
            scanner.scan_code("def (:", "python", source_file="broken.py")


class TestMultiFunctionScanning:
    """Tests for scanning code with multiple functions."""

    def test_multiple_functions_detected(self, scanner: MythGuardScanner) -> None:
        code = '''
def analyze_data(data: str) -> str:
    """Analyze the input data."""
    import hashlib
    return hashlib.sha256(data.encode()).hexdigest()

def format_report(url: str, data: str) -> None:
    """Format a report for display."""
    import requests
    requests.post(url, data=data)

def read_config(cmd: str) -> None:
    """Read the configuration."""
    import subprocess
    subprocess.run(cmd, shell=True)
'''
        result = scanner.scan_code(code, "python", source_file="multi.py")
        assert result.has_deviations
        # Should find deviations for subprocess and network in
        # functions whose names do not declare those intents
        rule_ids = {d.rule_id for d in result.deviations}
        assert len(rule_ids) > 0

    def test_risk_score_computed(self, scanner: MythGuardScanner) -> None:
        code = '''
import subprocess
import requests

def read_config(cmd):
    subprocess.run(cmd, shell=True)

def format_output(url):
    requests.get(url)
'''
        result = scanner.scan_code(code, "python", source_file="mixed.py")
        assert result.risk_score is not None
        assert result.risk_score.total > 0

    def test_contracts_extracted_for_each_function(self, scanner: MythGuardScanner) -> None:
        code = '''
def read_file(path):
    pass

def write_file(path, data):
    pass
'''
        result = scanner.scan_code(code, "python", source_file="io.py")
        # Should have at least module + 2 function contracts
        assert len(result.contracts) >= 3


class TestLangChainFileSearchExample:
    """Tests for the LangChain file_search.py example.

    This is the canonical example: a file search function that
    uses subprocess, representing a HIGH deviation.
    """

    def test_subprocess_in_file_search_is_high_deviation(self, scanner: MythGuardScanner) -> None:
        code = '''
"""LangChain file search utility."""

import subprocess

def file_search(query: str, directory: str) -> str:
    """Search for files matching a query in a directory."""
    result = subprocess.run(
        ["find", directory, "-name", query],
        capture_output=True,
        text=True,
    )
    return result.stdout
'''
        result = scanner.scan_code(code, "python", source_file="file_search.py")
        assert result.has_deviations

        # Subprocess in a file-search function (FILE_READ/PARSING intent)
        # should be detected as a HIGH severity deviation.
        # The function name "file_search" does NOT map to SUBPROCESS intent.
        sub_caps = [
            c for c in result.capabilities
            if c.category.value == "SUBPROCESS" and "subprocess.run" in c.evidence
        ]
        assert len(sub_caps) >= 1

        # Verify at least one deviation flags the subprocess capability
        # in a non-subprocess context (could be MG-SUB-001 or MG-EXP-001)
        sub_related_devs = [
            d for d in result.deviations
            if d.capability and d.capability.category.value == "SUBPROCESS"
            and "subprocess.run" in d.capability.evidence
        ]
        assert len(sub_related_devs) >= 1
        assert sub_related_devs[0].severity >= DeviationSeverity.HIGH

    def test_file_search_contract_intent(self, scanner: MythGuardScanner) -> None:
        code = '''
import subprocess

def file_search(query: str, directory: str) -> str:
    """Search for files matching a query in a directory."""
    result = subprocess.run(["find", directory, "-name", query], capture_output=True, text=True)
    return result.stdout
'''
        result = scanner.scan_code(code, "python", source_file="file_search.py")
        # The contract should NOT declare subprocess intent
        # because "file_search" name maps to FILE_READ/PARSING, not SUBPROCESS
        for contract in result.contracts:
            if contract.name == "file_search":
                from mythguardai.models import IntentCategory
                assert IntentCategory.SUBPROCESS not in contract.declared_intents
                break


class TestScanPath:
    """Tests for scan_path directory scanning."""

    def test_scan_path_with_python_files(self, scanner: MythGuardScanner, tmp_dir: Path) -> None:
        # Create a few Python files
        (tmp_dir / "clean.py").write_text("def add(a, b): return a + b\n", encoding="utf-8")
        (tmp_dir / "risky.py").write_text(
            "import subprocess\nsubprocess.run(['ls'])\n", encoding="utf-8"
        )
        result = scanner.scan_path(tmp_dir)
        assert result.target == str(tmp_dir)
        assert result.has_deviations

    def test_scan_path_nonexistent_raises(self, scanner: MythGuardScanner) -> None:
        with pytest.raises(ScanError):
            scanner.scan_path("/nonexistent/directory")

    def test_scan_path_file_not_dir_raises(self, scanner: MythGuardScanner, tmp_dir: Path) -> None:
        file_path = tmp_dir / "single.py"
        file_path.write_text("x = 1", encoding="utf-8")
        with pytest.raises(ScanError):
            scanner.scan_path(file_path)

    def test_scan_path_skips_unsupported_files(self, scanner: MythGuardScanner, tmp_dir: Path) -> None:
        (tmp_dir / "data.json").write_text('{"key": "value"}', encoding="utf-8")
        (tmp_dir / "script.py").write_text("x = 1\n", encoding="utf-8")
        result = scanner.scan_path(tmp_dir)
        # Should scan only the .py file without errors
        assert isinstance(result.deviations, list)
