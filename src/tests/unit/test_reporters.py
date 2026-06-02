"""Tests for all MythGuardAI reporters.

Covers: JSON reporter output structure, Markdown reporter formatting,
SARIF reporter v2.1.0 compliance, and empty results handling.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mythguardai.models import (
    Capability,
    CapabilityCategory,
    Deviation,
    DeviationSeverity,
    IntentCategory,
    ReachabilityStatus,
    RiskScore,
    ScanResult,
    SemanticContract,
    SourceLocation,
)
from mythguardai.reporters.json_reporter import JsonReporter
from mythguardai.reporters.markdown_reporter import MarkdownReporter
from mythguardai.reporters.sarif_reporter import SarifReporter


# ---------------------------------------------------------------------------
# Fixtures for reporter tests
# ---------------------------------------------------------------------------


@pytest.fixture
def deviation_with_details() -> Deviation:
    """A fully populated Deviation for reporter tests."""
    contract = SemanticContract(
        name="read_config",
        source="config.py",
        declared_intents={IntentCategory.FILE_READ},
        docstring="Read configuration from a file.",
        location=SourceLocation(file="config.py", line=10, col=0, end_line=15, end_col=30),
        confidence=1.0,
    )
    capability = Capability(
        category=CapabilityCategory.SUBPROCESS,
        description="Subprocess execution via subprocess.run",
        evidence="subprocess.run",
        location=SourceLocation(file="config.py", line=12, col=4),
        reachability=ReachabilityStatus.REACHABLE,
        confidence=0.9,
    )
    return Deviation(
        contract=contract,
        capability=capability,
        severity=DeviationSeverity.HIGH,
        rule_id="MG-SUB-001",
        message="'read_config' does not declare subprocess intent but contains subprocess capability",
        reachability=ReachabilityStatus.REACHABLE,
        location=SourceLocation(file="config.py", line=12, col=4),
    )


@pytest.fixture
def result_with_deviations(deviation_with_details: Deviation) -> ScanResult:
    """A ScanResult with deviations for reporter tests."""
    result = ScanResult(
        target="config.py",
        deviations=[deviation_with_details],
        contracts=[deviation_with_details.contract],  # type: ignore[list-item]
        capabilities=[deviation_with_details.capability],  # type: ignore[list-item]
        duration_ms=42.5,
        metadata={"scanner_version": "0.1.0"},
    )
    result.compute_risk_score()
    return result


@pytest.fixture
def empty_result() -> ScanResult:
    """A ScanResult with no deviations."""
    result = ScanResult(target="clean.py")
    result.compute_risk_score()
    return result


# ---------------------------------------------------------------------------
# JSON Reporter
# ---------------------------------------------------------------------------


class TestJsonReporter:
    """Tests for the JSON reporter output structure."""

    def test_output_is_valid_json(self, result_with_deviations: ScanResult) -> None:
        reporter = JsonReporter()
        output = reporter.render(result_with_deviations)
        data = json.loads(output)
        assert isinstance(data, dict)

    def test_output_contains_required_keys(self, result_with_deviations: ScanResult) -> None:
        reporter = JsonReporter()
        output = reporter.render(result_with_deviations)
        data = json.loads(output)
        assert "scan_id" in data
        assert "target" in data
        assert "timestamp" in data
        assert "deviations" in data
        assert "contracts" in data
        assert "capabilities" in data
        assert "risk_score" in data
        assert "duration_ms" in data
        assert "fingerprint" in data

    def test_deviations_are_serialized(self, result_with_deviations: ScanResult) -> None:
        reporter = JsonReporter()
        output = reporter.render(result_with_deviations)
        data = json.loads(output)
        assert len(data["deviations"]) == 1
        dev = data["deviations"][0]
        assert dev["rule_id"] == "MG-SUB-001"
        assert dev["severity"] == "HIGH"
        assert "message" in dev

    def test_risk_score_in_output(self, result_with_deviations: ScanResult) -> None:
        reporter = JsonReporter()
        output = reporter.render(result_with_deviations)
        data = json.loads(output)
        assert "risk_score" in data
        assert data["risk_score"]["total"] > 0

    def test_contracts_in_output(self, result_with_deviations: ScanResult) -> None:
        reporter = JsonReporter()
        output = reporter.render(result_with_deviations)
        data = json.loads(output)
        assert len(data["contracts"]) >= 1

    def test_capabilities_in_output(self, result_with_deviations: ScanResult) -> None:
        reporter = JsonReporter()
        output = reporter.render(result_with_deviations)
        data = json.loads(output)
        assert len(data["capabilities"]) >= 1

    def test_render_to_file(self, result_with_deviations: ScanResult, tmp_dir: Path) -> None:
        reporter = JsonReporter()
        file_path = tmp_dir / "report.json"
        reporter.render_to_file(result_with_deviations, str(file_path))
        assert file_path.exists()
        content = file_path.read_text(encoding="utf-8")
        data = json.loads(content)
        assert data["target"] == "config.py"

    def test_empty_result_json(self, empty_result: ScanResult) -> None:
        reporter = JsonReporter()
        output = reporter.render(empty_result)
        data = json.loads(output)
        assert data["deviations"] == []
        assert data["risk_score"]["total"] == 0.0


# ---------------------------------------------------------------------------
# Markdown Reporter
# ---------------------------------------------------------------------------


class TestMarkdownReporter:
    """Tests for the Markdown reporter formatting."""

    def test_output_contains_header(self, result_with_deviations: ScanResult) -> None:
        reporter = MarkdownReporter()
        output = reporter.render(result_with_deviations)
        assert "# MythGuardAI Security Report" in output

    def test_output_contains_executive_summary(self, result_with_deviations: ScanResult) -> None:
        reporter = MarkdownReporter()
        output = reporter.render(result_with_deviations)
        assert "## Executive Summary" in output
        assert "config.py" in output

    def test_output_contains_risk_breakdown(self, result_with_deviations: ScanResult) -> None:
        reporter = MarkdownReporter()
        output = reporter.render(result_with_deviations)
        assert "### Risk Breakdown" in output
        assert "CRITICAL" in output
        assert "HIGH" in output
        assert "MEDIUM" in output
        assert "LOW" in output

    def test_output_contains_deviations_section(self, result_with_deviations: ScanResult) -> None:
        reporter = MarkdownReporter()
        output = reporter.render(result_with_deviations)
        assert "## Deviations" in output
        assert "MG-SUB-001" in output

    def test_output_contains_fingerprint(self, result_with_deviations: ScanResult) -> None:
        reporter = MarkdownReporter()
        output = reporter.render(result_with_deviations)
        assert "Fingerprint:" in output

    def test_output_contains_contracts_table(self, result_with_deviations: ScanResult) -> None:
        reporter = MarkdownReporter()
        output = reporter.render(result_with_deviations)
        assert "## Semantic Contracts" in output
        assert "read_config" in output

    def test_output_contains_capabilities_table(self, result_with_deviations: ScanResult) -> None:
        reporter = MarkdownReporter()
        output = reporter.render(result_with_deviations)
        assert "## Discovered Capabilities" in output
        assert "SUBPROCESS" in output

    def test_risk_score_displayed(self, result_with_deviations: ScanResult) -> None:
        reporter = MarkdownReporter()
        output = reporter.render(result_with_deviations)
        assert "Risk Score" in output
        assert "Grade:" in output

    def test_render_to_file(self, result_with_deviations: ScanResult, tmp_dir: Path) -> None:
        reporter = MarkdownReporter()
        file_path = tmp_dir / "report.md"
        reporter.render_to_file(result_with_deviations, str(file_path))
        assert file_path.exists()
        content = file_path.read_text(encoding="utf-8")
        assert "# MythGuardAI Security Report" in content

    def test_empty_result_shows_no_deviations(self, empty_result: ScanResult) -> None:
        reporter = MarkdownReporter()
        output = reporter.render(empty_result)
        assert "## No Deviations Found" in output
        assert "No capability drift was detected" in output


# ---------------------------------------------------------------------------
# SARIF Reporter
# ---------------------------------------------------------------------------


class TestSarifReporter:
    """Tests for the SARIF reporter v2.1.0 compliance."""

    def test_output_is_valid_json(self, result_with_deviations: ScanResult) -> None:
        reporter = SarifReporter()
        output = reporter.render(result_with_deviations)
        data = json.loads(output)
        assert isinstance(data, dict)

    def test_sarif_version(self, result_with_deviations: ScanResult) -> None:
        reporter = SarifReporter()
        output = reporter.render(result_with_deviations)
        data = json.loads(output)
        assert data["version"] == "2.1.0"

    def test_sarif_schema(self, result_with_deviations: ScanResult) -> None:
        reporter = SarifReporter()
        output = reporter.render(result_with_deviations)
        data = json.loads(output)
        assert "$schema" in data
        assert "sarif-schema-2.1.0" in data["$schema"]

    def test_sarif_runs_structure(self, result_with_deviations: ScanResult) -> None:
        reporter = SarifReporter()
        output = reporter.render(result_with_deviations)
        data = json.loads(output)
        assert "runs" in data
        assert len(data["runs"]) == 1
        run = data["runs"][0]
        assert "tool" in run
        assert "results" in run

    def test_sarif_tool_driver(self, result_with_deviations: ScanResult) -> None:
        reporter = SarifReporter()
        output = reporter.render(result_with_deviations)
        data = json.loads(output)
        driver = data["runs"][0]["tool"]["driver"]
        assert driver["name"] == "MythGuardAI"
        assert "version" in driver
        assert "informationUri" in driver
        assert "rules" in driver

    def test_sarif_rules_populated(self, result_with_deviations: ScanResult) -> None:
        reporter = SarifReporter()
        output = reporter.render(result_with_deviations)
        data = json.loads(output)
        rules = data["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) >= 1
        rule_ids = [r["id"] for r in rules]
        assert "MG-SUB-001" in rule_ids

    def test_sarif_result_has_required_fields(self, result_with_deviations: ScanResult) -> None:
        reporter = SarifReporter()
        output = reporter.render(result_with_deviations)
        data = json.loads(output)
        results = data["runs"][0]["results"]
        assert len(results) >= 1
        result = results[0]
        assert "ruleId" in result
        assert "level" in result
        assert "message" in result
        assert "rank" in result

    def test_sarif_severity_mapping(self, result_with_deviations: ScanResult) -> None:
        reporter = SarifReporter()
        output = reporter.render(result_with_deviations)
        data = json.loads(output)
        results = data["runs"][0]["results"]
        high_results = [r for r in results if r["ruleId"] == "MG-SUB-001"]
        assert len(high_results) >= 1
        # HIGH severity maps to "error" in SARIF
        assert high_results[0]["level"] == "error"

    def test_sarif_result_location(self, result_with_deviations: ScanResult) -> None:
        reporter = SarifReporter()
        output = reporter.render(result_with_deviations)
        data = json.loads(output)
        results = data["runs"][0]["results"]
        assert len(results) >= 1
        result = results[0]
        assert "locations" in result
        assert len(result["locations"]) >= 1
        loc = result["locations"][0]["physicalLocation"]
        assert "artifactLocation" in loc
        assert "region" in loc

    def test_sarif_invocations(self, result_with_deviations: ScanResult) -> None:
        reporter = SarifReporter()
        output = reporter.render(result_with_deviations)
        data = json.loads(output)
        invocations = data["runs"][0]["invocations"]
        assert len(invocations) >= 1
        assert invocations[0]["executionSuccessful"] is True

    def test_sarif_run_properties(self, result_with_deviations: ScanResult) -> None:
        reporter = SarifReporter()
        output = reporter.render(result_with_deviations)
        data = json.loads(output)
        props = data["runs"][0]["properties"]
        assert "scanId" in props
        assert "target" in props
        assert "riskScore" in props
        assert "fingerprint" in props

    def test_sarif_result_properties(self, result_with_deviations: ScanResult) -> None:
        reporter = SarifReporter()
        output = reporter.render(result_with_deviations)
        data = json.loads(output)
        result = data["runs"][0]["results"][0]
        assert "properties" in result
        assert result["properties"]["severity"] == "HIGH"
        assert result["properties"]["reachability"] == "REACHABLE"

    def test_sarif_rule_has_help_uri(self, result_with_deviations: ScanResult) -> None:
        reporter = SarifReporter()
        output = reporter.render(result_with_deviations)
        data = json.loads(output)
        rules = data["runs"][0]["tool"]["driver"]["rules"]
        for rule in rules:
            assert "helpUri" in rule
            assert "github.com" in rule["helpUri"]

    def test_sarif_rule_has_tags(self, result_with_deviations: ScanResult) -> None:
        reporter = SarifReporter()
        output = reporter.render(result_with_deviations)
        data = json.loads(output)
        rules = data["runs"][0]["tool"]["driver"]["rules"]
        for rule in rules:
            assert "properties" in rule
            assert "tags" in rule["properties"]
            assert "security" in rule["properties"]["tags"]

    def test_render_to_file(self, result_with_deviations: ScanResult, tmp_dir: Path) -> None:
        reporter = SarifReporter()
        file_path = tmp_dir / "report.sarif"
        reporter.render_to_file(result_with_deviations, str(file_path))
        assert file_path.exists()
        content = file_path.read_text(encoding="utf-8")
        data = json.loads(content)
        assert data["version"] == "2.1.0"

    def test_empty_result_sarif(self, empty_result: ScanResult) -> None:
        reporter = SarifReporter()
        output = reporter.render(empty_result)
        data = json.loads(output)
        assert data["version"] == "2.1.0"
        assert data["runs"][0]["results"] == []
        assert data["runs"][0]["tool"]["driver"]["rules"] == []


# ---------------------------------------------------------------------------
# Empty results handling across all reporters
# ---------------------------------------------------------------------------


class TestEmptyResultsHandling:
    """Tests for empty results handling across all reporters."""

    def test_json_empty_results(self, empty_result: ScanResult) -> None:
        reporter = JsonReporter()
        output = reporter.render(empty_result)
        data = json.loads(output)
        assert data["deviations"] == []
        assert data["risk_score"]["total"] == 0.0
        assert data["risk_score"]["grade"] == "A"

    def test_markdown_empty_results(self, empty_result: ScanResult) -> None:
        reporter = MarkdownReporter()
        output = reporter.render(empty_result)
        assert "No Deviations Found" in output

    def test_sarif_empty_results(self, empty_result: ScanResult) -> None:
        reporter = SarifReporter()
        output = reporter.render(empty_result)
        data = json.loads(output)
        assert data["runs"][0]["results"] == []
