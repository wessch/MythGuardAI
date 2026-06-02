"""End-to-end integration tests for MythGuardAI.

Covers: full scan pipeline on sample code, deviation detection from
code to report, and deterministic replay verification.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from mythguardai.engine.scanner import MythGuardScanner
from mythguardai.models import DeviationSeverity, IntentCategory
from mythguardai.reporters.json_reporter import JsonReporter
from mythguardai.reporters.markdown_reporter import MarkdownReporter
from mythguardai.reporters.sarif_reporter import SarifReporter


# ---------------------------------------------------------------------------
# Sample code for end-to-end testing
# ---------------------------------------------------------------------------

RISKY_MODULE_CODE = '''"""Utility module for data processing."""

import subprocess
import os
import requests

def read_config(path: str) -> str:
    """Read configuration from a file."""
    result = subprocess.run(["cat", path], capture_output=True, text=True)
    return result.stdout

def analyze_data(data: str) -> str:
    """Analyze the input data."""
    import hashlib
    return hashlib.sha256(data.encode()).hexdigest()

def format_report(url: str) -> str:
    """Format a report for display."""
    response = requests.get(url)
    return response.text

def modify_file(path: str, mode: int) -> None:
    """Modify a file setting."""
    os.chmod(path, mode)

def get_env_setting(key: str) -> str:
    """Get an environment variable setting."""
    return os.getenv(key, "")

def save_output(path: str, data: str) -> None:
    """Save output data to a file."""
    with open(path, "w") as f:
        f.write(data)
'''

CLEAN_MODULE_CODE = '''"""Clean math utilities."""

def add(a: int, b: int) -> int:
    """Add two numbers."""
    return a + b

def multiply(a: int, b: int) -> int:
    """Multiply two numbers."""
    return a * b

def format_result(value: int) -> str:
    """Format a result as a string."""
    return f"Result: {value}"
'''


class TestFullScanPipeline:
    """End-to-end tests: code in, report out."""

    def test_full_scan_on_risky_code(self) -> None:
        """Scan a module with known risks and verify the full pipeline."""
        scanner = MythGuardScanner()
        result = scanner.scan_code(
            RISKY_MODULE_CODE, "python", source_file="risky.py"
        )

        # Should have deviations
        assert result.has_deviations
        assert len(result.deviations) > 0

        # Should have contracts for each function + module
        assert len(result.contracts) >= 7  # module + 6 functions

        # Should have capabilities detected
        assert len(result.capabilities) > 0

        # Risk score should be computed
        assert result.risk_score.total > 0

        # Should find subprocess deviation in read_config
        # (read_config declares FILE_READ, not SUBPROCESS)
        sub_devs = [d for d in result.deviations if d.rule_id == "MG-SUB-001"]
        assert len(sub_devs) >= 1

        # Should find network deviation in format_report
        # (format_report declares COMPUTATION, not NETWORK)
        net_devs = [d for d in result.deviations if d.rule_id == "MG-NET-001"]
        assert len(net_devs) >= 1

        # Should find privilege deviation in modify_file
        # (modify_file does not declare PRIVILEGE intent)
        priv_devs = [d for d in result.deviations if d.rule_id == "MG-PRIV-001"]
        assert len(priv_devs) >= 1

    def test_clean_code_no_high_deviations(self) -> None:
        """Clean code should have no high or critical deviations."""
        scanner = MythGuardScanner()
        result = scanner.scan_code(
            CLEAN_MODULE_CODE, "python", source_file="clean.py"
        )

        high_risk = [
            d for d in result.deviations
            if d.severity >= DeviationSeverity.HIGH
        ]
        assert len(high_risk) == 0

    def test_scan_directory_end_to_end(self) -> None:
        """Scan a directory with multiple files."""
        scanner = MythGuardScanner()
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            (td_path / "clean.py").write_text(CLEAN_MODULE_CODE, encoding="utf-8")
            (td_path / "risky.py").write_text(RISKY_MODULE_CODE, encoding="utf-8")

            result = scanner.scan_path(td_path)
            assert result.has_deviations
            assert result.risk_score.total > 0
            assert len(result.contracts) > 0
            assert len(result.capabilities) > 0


class TestDeviationDetectionFromCodeToReport:
    """Verify deviation detection from code to each report format."""

    def test_json_report_contains_deviations(self) -> None:
        scanner = MythGuardScanner()
        result = scanner.scan_code(
            RISKY_MODULE_CODE, "python", source_file="risky.py"
        )
        reporter = JsonReporter()
        output = reporter.render(result)
        data = json.loads(output)

        assert len(data["deviations"]) > 0
        deviation_rule_ids = {d["rule_id"] for d in data["deviations"]}
        assert "MG-SUB-001" in deviation_rule_ids

    def test_markdown_report_contains_deviations(self) -> None:
        scanner = MythGuardScanner()
        result = scanner.scan_code(
            RISKY_MODULE_CODE, "python", source_file="risky.py"
        )
        reporter = MarkdownReporter()
        output = reporter.render(result)

        assert "## Deviations" in output
        # Subprocess or network deviations should appear
        assert "MG-SUB-001" in output or "MG-NET-001" in output
        assert "HIGH" in output

    def test_sarif_report_contains_deviations(self) -> None:
        scanner = MythGuardScanner()
        result = scanner.scan_code(
            RISKY_MODULE_CODE, "python", source_file="risky.py"
        )
        reporter = SarifReporter()
        output = reporter.render(result)
        data = json.loads(output)

        assert len(data["runs"][0]["results"]) > 0
        rule_ids = {r["ruleId"] for r in data["runs"][0]["results"]}
        assert "MG-SUB-001" in rule_ids

    def test_all_reporters_on_file_output(self) -> None:
        """All three reporters can write to files."""
        scanner = MythGuardScanner()
        result = scanner.scan_code(
            RISKY_MODULE_CODE, "python", source_file="risky.py"
        )

        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)

            json_path = td_path / "report.json"
            JsonReporter().render_to_file(result, str(json_path))
            assert json_path.exists()

            md_path = td_path / "report.md"
            MarkdownReporter().render_to_file(result, str(md_path))
            assert md_path.exists()

            sarif_path = td_path / "report.sarif"
            SarifReporter().render_to_file(result, str(sarif_path))
            assert sarif_path.exists()

            # Verify content is valid
            json_data = json.loads(json_path.read_text(encoding="utf-8"))
            assert json_data["target"] == "risky.py"

            sarif_data = json.loads(sarif_path.read_text(encoding="utf-8"))
            assert sarif_data["version"] == "2.1.0"


class TestDeterministicReplay:
    """Verify that scanning the same code twice produces consistent results.

    Note: Deviation IDs are randomly generated, so fingerprints may differ
    between runs. We verify structural determinism instead: same deviation
    count, same rule IDs, same severities, and same risk scores.
    """

    def test_same_code_same_deviation_structure(self) -> None:
        scanner = MythGuardScanner()
        result1 = scanner.scan_code(
            RISKY_MODULE_CODE, "python", source_file="risky.py"
        )
        result2 = scanner.scan_code(
            RISKY_MODULE_CODE, "python", source_file="risky.py"
        )

        # Same number of deviations
        assert len(result1.deviations) == len(result2.deviations)

        # Same rule IDs (sorted for deterministic comparison)
        rule_ids1 = sorted(d.rule_id for d in result1.deviations)
        rule_ids2 = sorted(d.rule_id for d in result2.deviations)
        assert rule_ids1 == rule_ids2

        # Same severities per rule
        for d1 in result1.deviations:
            matching = [
                d2 for d2 in result2.deviations
                if d2.rule_id == d1.rule_id
                and d2.severity == d1.severity
                and d2.capability is not None
                and d1.capability is not None
                and d2.capability.evidence == d1.capability.evidence
            ]
            assert len(matching) >= 1, (
                f"No matching deviation for {d1.rule_id} "
                f"with severity {d1.severity.value}"
            )

    def test_same_code_same_risk_score(self) -> None:
        scanner = MythGuardScanner()
        result1 = scanner.scan_code(
            RISKY_MODULE_CODE, "python", source_file="risky.py"
        )
        result2 = scanner.scan_code(
            RISKY_MODULE_CODE, "python", source_file="risky.py"
        )
        assert result1.risk_score.total == result2.risk_score.total
        assert result1.risk_score.grade == result2.risk_score.grade

    def test_different_code_different_findings(self) -> None:
        """Different code should produce different deviation sets."""
        scanner = MythGuardScanner()
        result1 = scanner.scan_code(
            RISKY_MODULE_CODE, "python", source_file="risky.py"
        )
        result2 = scanner.scan_code(
            CLEAN_MODULE_CODE, "python", source_file="clean.py"
        )
        # Risky code should have more deviations than clean code
        assert len(result1.deviations) > len(result2.deviations)
        assert result1.risk_score.total > result2.risk_score.total

    def test_deterministic_with_file_scanning(self) -> None:
        """File-based scanning produces consistent deviation structure."""
        scanner = MythGuardScanner()
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            file_path = td_path / "test.py"
            file_path.write_text(RISKY_MODULE_CODE, encoding="utf-8")

            result1 = scanner.scan_file(file_path)
            result2 = scanner.scan_file(file_path)

            # Same number of deviations
            assert len(result1.deviations) == len(result2.deviations)

            # Same rule IDs
            rule_ids1 = sorted(d.rule_id for d in result1.deviations)
            rule_ids2 = sorted(d.rule_id for d in result2.deviations)
            assert rule_ids1 == rule_ids2

            # Same risk score
            assert result1.risk_score.total == result2.risk_score.total
