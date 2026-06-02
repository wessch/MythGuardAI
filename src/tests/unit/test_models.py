"""Tests for MythGuardAI core data models.

Covers: SemanticContract, DeviationSeverity, RiskScore, ScanResult,
SourceLocation, Fingerprint determinism, and serialization round-trips.
"""

from __future__ import annotations

import pytest

from mythguardai.models import (
    CAPABILITY_TO_INTENT,
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


# ---------------------------------------------------------------------------
# SemanticContract
# ---------------------------------------------------------------------------


class TestSemanticContract:
    """Tests for SemanticContract creation and serialization."""

    def test_creation_with_defaults(self) -> None:
        contract = SemanticContract(name="foo", source="bar.py")
        assert contract.name == "foo"
        assert contract.source == "bar.py"
        assert contract.declared_intents == set()
        assert contract.docstring is None
        assert contract.type_annotations == {}
        assert contract.decorators == []
        assert contract.location is None
        assert contract.confidence == 1.0
        assert contract.metadata == {}

    def test_creation_with_all_fields(self) -> None:
        loc = SourceLocation(file="x.py", line=1, col=0, end_line=5, end_col=10)
        contract = SemanticContract(
            name="fetch_data",
            source="x.py",
            declared_intents={IntentCategory.NETWORK, IntentCategory.FILE_READ},
            docstring="Fetch data from remote API.",
            type_annotations={"url": "str"},
            decorators=["retry"],
            location=loc,
            confidence=0.9,
            metadata={"baz": 42},
        )
        assert IntentCategory.NETWORK in contract.declared_intents
        assert IntentCategory.FILE_READ in contract.declared_intents
        assert contract.docstring == "Fetch data from remote API."
        assert contract.location is not None
        assert contract.location.line == 1

    def test_to_dict_round_trip(self) -> None:
        loc = SourceLocation(file="a.py", line=3, col=0)
        original = SemanticContract(
            name="save_config",
            source="a.py",
            declared_intents={IntentCategory.FILE_WRITE},
            docstring="Save config to disk.",
            type_annotations={"path": "Path"},
            decorators=[],
            location=loc,
            confidence=0.85,
            metadata={"key": "val"},
        )
        data = original.to_dict()
        restored = SemanticContract.from_dict(data)
        assert restored.name == original.name
        assert restored.source == original.source
        assert restored.declared_intents == original.declared_intents
        assert restored.docstring == original.docstring
        assert restored.type_annotations == original.type_annotations
        assert restored.confidence == original.confidence
        assert restored.metadata == original.metadata
        assert restored.location is not None
        assert restored.location.file == loc.file

    def test_to_dict_intents_serialized_as_values(self) -> None:
        contract = SemanticContract(
            name="test",
            source="t.py",
            declared_intents={IntentCategory.NETWORK, IntentCategory.SUBPROCESS},
        )
        data = contract.to_dict()
        assert isinstance(data["declared_intents"], list)
        assert "NETWORK" in data["declared_intents"]
        assert "SUBPROCESS" in data["declared_intents"]

    def test_from_dict_missing_optional_fields(self) -> None:
        data = {"name": "fn", "source": "f.py"}
        contract = SemanticContract.from_dict(data)
        assert contract.name == "fn"
        assert contract.declared_intents == set()
        assert contract.confidence == 1.0


# ---------------------------------------------------------------------------
# DeviationSeverity ordering
# ---------------------------------------------------------------------------


class TestDeviationSeverity:
    """Tests for DeviationSeverity comparison ordering."""

    def test_ordering_low_to_critical(self) -> None:
        assert DeviationSeverity.LOW < DeviationSeverity.MEDIUM
        assert DeviationSeverity.MEDIUM < DeviationSeverity.HIGH
        assert DeviationSeverity.HIGH < DeviationSeverity.CRITICAL

    def test_ge_comparisons(self) -> None:
        assert DeviationSeverity.HIGH >= DeviationSeverity.MEDIUM
        assert DeviationSeverity.HIGH >= DeviationSeverity.HIGH
        assert not (DeviationSeverity.LOW >= DeviationSeverity.MEDIUM)

    def test_le_comparisons(self) -> None:
        assert DeviationSeverity.LOW <= DeviationSeverity.MEDIUM
        assert DeviationSeverity.MEDIUM <= DeviationSeverity.MEDIUM
        assert not (DeviationSeverity.CRITICAL <= DeviationSeverity.HIGH)

    def test_gt_comparisons(self) -> None:
        assert DeviationSeverity.CRITICAL > DeviationSeverity.HIGH
        assert not (DeviationSeverity.LOW > DeviationSeverity.LOW)

    def test_lt_comparisons(self) -> None:
        assert DeviationSeverity.LOW < DeviationSeverity.HIGH
        assert not (DeviationSeverity.HIGH < DeviationSeverity.HIGH)

    def test_comparison_with_non_severity_returns_not_implemented(self) -> None:
        result = DeviationSeverity.HIGH.__ge__("not_a_severity")  # type: ignore[arg-type]
        assert result is NotImplemented

    def test_severity_values(self) -> None:
        assert DeviationSeverity.LOW.value == "LOW"
        assert DeviationSeverity.MEDIUM.value == "MEDIUM"
        assert DeviationSeverity.HIGH.value == "HIGH"
        assert DeviationSeverity.CRITICAL.value == "CRITICAL"


# ---------------------------------------------------------------------------
# RiskScore
# ---------------------------------------------------------------------------


class TestRiskScore:
    """Tests for RiskScore computation."""

    def test_empty_deviations_gives_zero_score(self) -> None:
        score = RiskScore.from_deviations([])
        assert score.total == 0.0
        assert score.critical_count == 0
        assert score.high_count == 0
        assert score.medium_count == 0
        assert score.low_count == 0

    def test_single_low_deviation(self) -> None:
        dev = Deviation(severity=DeviationSeverity.LOW)
        score = RiskScore.from_deviations([dev])
        assert score.low_count == 1
        assert score.total == 2.0

    def test_single_medium_deviation(self) -> None:
        dev = Deviation(severity=DeviationSeverity.MEDIUM)
        score = RiskScore.from_deviations([dev])
        assert score.medium_count == 1
        assert score.total == 7.0

    def test_single_high_deviation(self) -> None:
        dev = Deviation(severity=DeviationSeverity.HIGH)
        score = RiskScore.from_deviations([dev])
        assert score.high_count == 1
        assert score.total == 15.0

    def test_single_critical_deviation(self) -> None:
        dev = Deviation(severity=DeviationSeverity.CRITICAL)
        score = RiskScore.from_deviations([dev])
        assert score.critical_count == 1
        assert score.total == 25.0

    def test_mixed_severity_counts(self) -> None:
        devs = [
            Deviation(severity=DeviationSeverity.CRITICAL),
            Deviation(severity=DeviationSeverity.HIGH),
            Deviation(severity=DeviationSeverity.HIGH),
            Deviation(severity=DeviationSeverity.MEDIUM),
            Deviation(severity=DeviationSeverity.LOW),
            Deviation(severity=DeviationSeverity.LOW),
        ]
        score = RiskScore.from_deviations(devs)
        assert score.critical_count == 1
        assert score.high_count == 2
        assert score.medium_count == 1
        assert score.low_count == 2
        # 25 + 15*2 + 7 + 2*2 = 25 + 30 + 7 + 4 = 66
        assert score.total == 66.0

    def test_score_capped_at_100(self) -> None:
        devs = [Deviation(severity=DeviationSeverity.CRITICAL) for _ in range(10)]
        score = RiskScore.from_deviations(devs)
        # 25 * 10 = 250, capped at 100
        assert score.total == 100.0

    def test_grade_a(self) -> None:
        score = RiskScore(total=0.0)
        assert score.grade == "A"
        score = RiskScore(total=20.0)
        assert score.grade == "A"

    def test_grade_b(self) -> None:
        score = RiskScore(total=21.0)
        assert score.grade == "B"
        score = RiskScore(total=40.0)
        assert score.grade == "B"

    def test_grade_c(self) -> None:
        score = RiskScore(total=41.0)
        assert score.grade == "C"

    def test_grade_d(self) -> None:
        score = RiskScore(total=61.0)
        assert score.grade == "D"

    def test_grade_f(self) -> None:
        score = RiskScore(total=81.0)
        assert score.grade == "F"
        score = RiskScore(total=100.0)
        assert score.grade == "F"

    def test_to_dict_contains_grade(self) -> None:
        score = RiskScore(total=15.0, low_count=5)
        data = score.to_dict()
        assert "grade" in data
        assert data["grade"] == "A"
        assert data["total"] == 15.0
        assert data["low_count"] == 5


# ---------------------------------------------------------------------------
# ScanResult
# ---------------------------------------------------------------------------


class TestScanResult:
    """Tests for ScanResult aggregation."""

    def test_empty_result(self) -> None:
        result = ScanResult(target="clean.py")
        assert not result.has_deviations
        assert not result.has_critical
        assert result.risk_score.total == 0.0

    def test_has_deviations(self) -> None:
        result = ScanResult(
            target="x.py",
            deviations=[Deviation(severity=DeviationSeverity.LOW)],
        )
        assert result.has_deviations

    def test_has_critical(self) -> None:
        result = ScanResult(
            target="x.py",
            deviations=[Deviation(severity=DeviationSeverity.CRITICAL)],
        )
        assert result.has_critical

    def test_has_critical_false_when_only_high(self) -> None:
        result = ScanResult(
            target="x.py",
            deviations=[Deviation(severity=DeviationSeverity.HIGH)],
        )
        assert not result.has_critical

    def test_compute_risk_score(self) -> None:
        result = ScanResult(
            target="x.py",
            deviations=[
                Deviation(severity=DeviationSeverity.HIGH),
                Deviation(severity=DeviationSeverity.MEDIUM),
            ],
        )
        result.compute_risk_score()
        assert result.risk_score.total == 22.0  # 15 + 7
        assert result.risk_score.high_count == 1
        assert result.risk_score.medium_count == 1

    def test_filter_by_severity(self) -> None:
        result = ScanResult(
            target="x.py",
            deviations=[
                Deviation(severity=DeviationSeverity.CRITICAL),
                Deviation(severity=DeviationSeverity.HIGH),
                Deviation(severity=DeviationSeverity.MEDIUM),
                Deviation(severity=DeviationSeverity.LOW),
            ],
        )
        filtered = result.filter_by_severity(DeviationSeverity.HIGH)
        assert len(filtered) == 2
        assert all(d.severity >= DeviationSeverity.HIGH for d in filtered)

    def test_filter_by_severity_critical_only(self) -> None:
        result = ScanResult(
            target="x.py",
            deviations=[
                Deviation(severity=DeviationSeverity.CRITICAL),
                Deviation(severity=DeviationSeverity.LOW),
            ],
        )
        filtered = result.filter_by_severity(DeviationSeverity.CRITICAL)
        assert len(filtered) == 1
        assert filtered[0].severity == DeviationSeverity.CRITICAL

    def test_to_dict_and_from_dict_round_trip(self) -> None:
        cap = Capability(
            category=CapabilityCategory.SUBPROCESS,
            description="Subprocess call",
            evidence="subprocess.run",
            location=SourceLocation(file="a.py", line=5),
        )
        contract = SemanticContract(
            name="run_task",
            source="a.py",
            declared_intents={IntentCategory.SUBPROCESS},
        )
        dev = Deviation(
            contract=contract,
            capability=cap,
            severity=DeviationSeverity.HIGH,
            rule_id="MG-SUB-001",
            message="Test deviation",
        )
        result = ScanResult(
            target="a.py",
            deviations=[dev],
            contracts=[contract],
            capabilities=[cap],
            duration_ms=10.0,
            metadata={"version": "0.1.0"},
        )
        result.compute_risk_score()

        data = result.to_dict()
        restored = ScanResult.from_dict(data)

        assert restored.target == "a.py"
        assert len(restored.deviations) == 1
        assert restored.deviations[0].rule_id == "MG-SUB-001"
        assert len(restored.contracts) == 1
        assert len(restored.capabilities) == 1
        assert restored.duration_ms == 10.0
        assert restored.risk_score.total == result.risk_score.total

    def test_scan_id_is_populated(self) -> None:
        result = ScanResult()
        assert result.scan_id != ""
        assert len(result.scan_id) > 0

    def test_timestamp_is_populated(self) -> None:
        result = ScanResult()
        assert result.timestamp != ""
        assert "T" in result.timestamp  # ISO 8601 format


# ---------------------------------------------------------------------------
# Fingerprint determinism
# ---------------------------------------------------------------------------


class TestFingerprint:
    """Tests for ScanResult fingerprint determinism."""

    def test_same_deviations_produce_same_fingerprint(self) -> None:
        dev1 = Deviation(
            id="abc",
            severity=DeviationSeverity.HIGH,
            rule_id="MG-SUB-001",
            capability=Capability(
                category=CapabilityCategory.SUBPROCESS,
                description="test",
                evidence="subprocess.run",
            ),
            reachability=ReachabilityStatus.REACHABLE,
        )
        dev2 = Deviation(
            id="abc",
            severity=DeviationSeverity.HIGH,
            rule_id="MG-SUB-001",
            capability=Capability(
                category=CapabilityCategory.SUBPROCESS,
                description="test",
                evidence="subprocess.run",
            ),
            reachability=ReachabilityStatus.REACHABLE,
        )
        result1 = ScanResult(deviations=[dev1])
        result2 = ScanResult(deviations=[dev2])
        assert result1.fingerprint() == result2.fingerprint()

    def test_different_deviations_produce_different_fingerprint(self) -> None:
        dev1 = Deviation(
            id="abc",
            severity=DeviationSeverity.HIGH,
            rule_id="MG-SUB-001",
            capability=Capability(
                category=CapabilityCategory.SUBPROCESS,
                description="test",
                evidence="subprocess.run",
            ),
            reachability=ReachabilityStatus.REACHABLE,
        )
        dev2 = Deviation(
            id="xyz",
            severity=DeviationSeverity.LOW,
            rule_id="MG-FW-001",
            capability=Capability(
                category=CapabilityCategory.FILE_WRITE,
                description="test",
                evidence="open('w')",
            ),
            reachability=ReachabilityStatus.REACHABLE,
        )
        result1 = ScanResult(deviations=[dev1])
        result2 = ScanResult(deviations=[dev2])
        assert result1.fingerprint() != result2.fingerprint()

    def test_fingerprint_is_sha256_hex(self) -> None:
        result = ScanResult(deviations=[Deviation(rule_id="MG-SUB-001", severity=DeviationSeverity.HIGH)])
        fp = result.fingerprint()
        assert len(fp) == 64  # SHA-256 hex digest length
        assert all(c in "0123456789abcdef" for c in fp)

    def test_empty_result_fingerprint(self) -> None:
        result1 = ScanResult()
        result2 = ScanResult()
        assert result1.fingerprint() == result2.fingerprint()


# ---------------------------------------------------------------------------
# SourceLocation
# ---------------------------------------------------------------------------


class TestSourceLocation:
    """Tests for SourceLocation creation and validation."""

    def test_creation_with_defaults(self) -> None:
        loc = SourceLocation(file="test.py")
        assert loc.file == "test.py"
        assert loc.line == 0
        assert loc.col == -1
        assert loc.end_line == 0
        assert loc.end_col == -1

    def test_creation_with_all_fields(self) -> None:
        loc = SourceLocation(file="a.py", line=10, col=4, end_line=15, end_col=20)
        assert loc.file == "a.py"
        assert loc.line == 10
        assert loc.col == 4
        assert loc.end_line == 15
        assert loc.end_col == 20

    def test_to_dict_round_trip(self) -> None:
        loc = SourceLocation(file="b.py", line=5, col=2, end_line=8, end_col=10)
        data = loc.to_dict()
        restored = SourceLocation.from_dict(data)
        assert restored == loc

    def test_from_dict_with_defaults(self) -> None:
        data = {"file": "c.py"}
        loc = SourceLocation.from_dict(data)
        assert loc.file == "c.py"
        assert loc.line == 0
        assert loc.col == -1

    def test_frozen(self) -> None:
        loc = SourceLocation(file="f.py", line=1)
        with pytest.raises(AttributeError):
            loc.file = "other.py"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Capability and CAPABILITY_TO_INTENT mapping
# ---------------------------------------------------------------------------


class TestCapability:
    """Tests for Capability model and intent mapping."""

    def test_intent_category_mapping(self) -> None:
        cap = Capability(
            category=CapabilityCategory.SUBPROCESS,
            description="test",
            evidence="subprocess.run",
        )
        assert cap.intent_category == IntentCategory.SUBPROCESS

    def test_intent_category_for_network_client(self) -> None:
        cap = Capability(
            category=CapabilityCategory.NETWORK_CLIENT,
            description="test",
            evidence="requests.get",
        )
        assert cap.intent_category == IntentCategory.NETWORK

    def test_intent_category_for_unknown(self) -> None:
        cap = Capability(
            category=CapabilityCategory.UNKNOWN,
            description="test",
            evidence="unknown",
        )
        assert cap.intent_category == IntentCategory.UNKNOWN

    def test_capability_to_intent_map_covers_all_categories(self) -> None:
        """Every CapabilityCategory should have a mapping in CAPABILITY_TO_INTENT."""
        for cat in CapabilityCategory:
            assert cat in CAPABILITY_TO_INTENT, f"Missing mapping for {cat}"

    def test_to_dict_round_trip(self) -> None:
        cap = Capability(
            category=CapabilityCategory.FILE_WRITE,
            description="Write to file",
            evidence="open('w')",
            location=SourceLocation(file="x.py", line=3),
            reachability=ReachabilityStatus.REACHABLE,
            confidence=0.85,
            metadata={"foo": "bar"},
        )
        data = cap.to_dict()
        restored = Capability.from_dict(data)
        assert restored.category == cap.category
        assert restored.description == cap.description
        assert restored.evidence == cap.evidence
        assert restored.confidence == cap.confidence
        assert restored.reachability == cap.reachability


# ---------------------------------------------------------------------------
# Deviation
# ---------------------------------------------------------------------------


class TestDeviation:
    """Tests for Deviation model."""

    def test_default_id_generated(self) -> None:
        dev = Deviation()
        assert dev.id != ""
        assert len(dev.id) == 12

    def test_to_dict_round_trip(self) -> None:
        dev = Deviation(
            severity=DeviationSeverity.HIGH,
            rule_id="MG-SUB-001",
            message="Subprocess found",
            capability=Capability(
                category=CapabilityCategory.SUBPROCESS,
                description="subprocess",
                evidence="subprocess.run",
            ),
        )
        data = dev.to_dict()
        restored = Deviation.from_dict(data)
        assert restored.severity == dev.severity
        assert restored.rule_id == dev.rule_id
        assert restored.message == dev.message
        assert restored.capability is not None
        assert restored.capability.category == CapabilityCategory.SUBPROCESS
