"""Tests for the PolicyEngine.

Covers: each built-in policy evaluation, custom policy loading,
deterministic replay, severity threshold filtering, and rule IDs.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from mythguardai.exceptions import PolicyError
from mythguardai.models import (
    Capability,
    CapabilityCategory,
    Deviation,
    DeviationSeverity,
    IntentCategory,
    ReachabilityStatus,
    SemanticContract,
    SourceLocation,
)
from mythguardai.policies.policy_engine import (
    CapabilityExpansionPolicy,
    FileWritePolicy,
    NetworkAccessPolicy,
    Policy,
    PolicyEngine,
    PrivilegeEscalationPolicy,
    SubprocessExecutionPolicy,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_contract(
    name: str = "test_func",
    intents: set[IntentCategory] | None = None,
) -> SemanticContract:
    """Create a SemanticContract with given intents."""
    return SemanticContract(
        name=name,
        source="test.py",
        declared_intents=intents or set(),
        location=SourceLocation(file="test.py", line=1, end_line=10),
    )


def _make_capability(
    category: CapabilityCategory,
    evidence: str = "test",
) -> Capability:
    """Create a Capability with given category."""
    return Capability(
        category=category,
        description=f"Test {category.value} capability",
        evidence=evidence,
        location=SourceLocation(file="test.py", line=5),
        reachability=ReachabilityStatus.REACHABLE,
    )


# ---------------------------------------------------------------------------
# SubprocessExecutionPolicy (MG-SUB-001)
# ---------------------------------------------------------------------------


class TestSubprocessExecutionPolicy:
    """Tests for the subprocess execution policy."""

    def test_flags_subprocess_in_non_execution_context(self) -> None:
        policy = SubprocessExecutionPolicy()
        contract = _make_contract("read_config", {IntentCategory.FILE_READ})
        caps = [_make_capability(CapabilityCategory.SUBPROCESS, "subprocess.run")]
        deviations = policy.evaluate(contract, caps)
        assert len(deviations) == 1
        assert deviations[0].rule_id == "MG-SUB-001"
        assert deviations[0].severity == DeviationSeverity.HIGH

    def test_no_deviation_when_subprocess_intent_declared(self) -> None:
        policy = SubprocessExecutionPolicy()
        contract = _make_contract("run_command", {IntentCategory.SUBPROCESS})
        caps = [_make_capability(CapabilityCategory.SUBPROCESS, "subprocess.run")]
        deviations = policy.evaluate(contract, caps)
        assert len(deviations) == 0

    def test_no_deviation_when_dynamic_exec_intent_declared(self) -> None:
        policy = SubprocessExecutionPolicy()
        contract = _make_contract("eval_code", {IntentCategory.DYNAMIC_EXEC})
        caps = [_make_capability(CapabilityCategory.SUBPROCESS, "subprocess.run")]
        deviations = policy.evaluate(contract, caps)
        assert len(deviations) == 0

    def test_no_deviation_when_privilege_intent_declared(self) -> None:
        policy = SubprocessExecutionPolicy()
        contract = _make_contract("admin_run", {IntentCategory.PRIVILEGE})
        caps = [_make_capability(CapabilityCategory.SUBPROCESS, "subprocess.run")]
        deviations = policy.evaluate(contract, caps)
        assert len(deviations) == 0

    def test_no_subprocess_capability_no_deviation(self) -> None:
        policy = SubprocessExecutionPolicy()
        contract = _make_contract("read_data", {IntentCategory.FILE_READ})
        caps = [_make_capability(CapabilityCategory.FILE_READ, "open")]
        deviations = policy.evaluate(contract, caps)
        assert len(deviations) == 0


# ---------------------------------------------------------------------------
# FileWritePolicy (MG-FW-001)
# ---------------------------------------------------------------------------


class TestFileWritePolicy:
    """Tests for the file write policy."""

    def test_flags_file_write_in_read_only_context(self) -> None:
        policy = FileWritePolicy()
        contract = _make_contract("read_config", {IntentCategory.FILE_READ})
        caps = [_make_capability(CapabilityCategory.FILE_WRITE, "open('w')")]
        deviations = policy.evaluate(contract, caps)
        assert len(deviations) == 1
        assert deviations[0].rule_id == "MG-FW-001"
        assert deviations[0].severity == DeviationSeverity.HIGH

    def test_flags_temp_file_in_read_only_context(self) -> None:
        policy = FileWritePolicy()
        contract = _make_contract("read_config", {IntentCategory.FILE_READ})
        caps = [_make_capability(CapabilityCategory.TEMP_FILE, "tempfile.mktemp")]
        deviations = policy.evaluate(contract, caps)
        assert len(deviations) >= 1

    def test_no_deviation_when_write_intent_declared(self) -> None:
        policy = FileWritePolicy()
        contract = _make_contract("save_data", {IntentCategory.FILE_WRITE})
        caps = [_make_capability(CapabilityCategory.FILE_WRITE, "open('w')")]
        deviations = policy.evaluate(contract, caps)
        assert len(deviations) == 0

    def test_medium_severity_without_read_intent(self) -> None:
        policy = FileWritePolicy()
        contract = _make_contract("process", {IntentCategory.COMPUTATION})
        caps = [_make_capability(CapabilityCategory.FILE_WRITE, "open('w')")]
        deviations = policy.evaluate(contract, caps)
        assert len(deviations) == 1
        assert deviations[0].severity == DeviationSeverity.MEDIUM

    def test_no_deviation_for_subprocess_intent(self) -> None:
        policy = FileWritePolicy()
        contract = _make_contract("run_task", {IntentCategory.SUBPROCESS})
        caps = [_make_capability(CapabilityCategory.FILE_WRITE, "open('w')")]
        deviations = policy.evaluate(contract, caps)
        assert len(deviations) == 0

    def test_flags_file_system_manipulation(self) -> None:
        policy = FileWritePolicy()
        contract = _make_contract("read_config", {IntentCategory.FILE_READ})
        caps = [_make_capability(CapabilityCategory.FILE_SYSTEM_MANIPULATION, "os.rename")]
        deviations = policy.evaluate(contract, caps)
        assert len(deviations) >= 1


# ---------------------------------------------------------------------------
# NetworkAccessPolicy (MG-NET-001)
# ---------------------------------------------------------------------------


class TestNetworkAccessPolicy:
    """Tests for the network access policy."""

    def test_flags_network_client_in_non_network_context(self) -> None:
        policy = NetworkAccessPolicy()
        contract = _make_contract("compute", {IntentCategory.COMPUTATION})
        caps = [_make_capability(CapabilityCategory.NETWORK_CLIENT, "requests.get")]
        deviations = policy.evaluate(contract, caps)
        assert len(deviations) == 1
        assert deviations[0].rule_id == "MG-NET-001"
        assert deviations[0].severity == DeviationSeverity.HIGH

    def test_flags_network_server_as_critical(self) -> None:
        policy = NetworkAccessPolicy()
        contract = _make_contract("compute", {IntentCategory.COMPUTATION})
        caps = [_make_capability(CapabilityCategory.NETWORK_SERVER, "HTTPServer")]
        deviations = policy.evaluate(contract, caps)
        assert len(deviations) == 1
        assert deviations[0].severity == DeviationSeverity.CRITICAL

    def test_no_deviation_when_network_intent_declared(self) -> None:
        policy = NetworkAccessPolicy()
        contract = _make_contract("fetch_data", {IntentCategory.NETWORK})
        caps = [_make_capability(CapabilityCategory.NETWORK_CLIENT, "requests.get")]
        deviations = policy.evaluate(contract, caps)
        assert len(deviations) == 0


# ---------------------------------------------------------------------------
# PrivilegeEscalationPolicy (MG-PRIV-001)
# ---------------------------------------------------------------------------


class TestPrivilegeEscalationPolicy:
    """Tests for the privilege escalation policy."""

    def test_flags_privilege_in_non_privileged_context(self) -> None:
        policy = PrivilegeEscalationPolicy()
        contract = _make_contract("read_data", {IntentCategory.FILE_READ})
        caps = [_make_capability(CapabilityCategory.PRIVILEGE_ESCALATION, "os.chmod")]
        deviations = policy.evaluate(contract, caps)
        assert len(deviations) == 1
        assert deviations[0].rule_id == "MG-PRIV-001"
        assert deviations[0].severity == DeviationSeverity.CRITICAL

    def test_flags_signal_handling(self) -> None:
        policy = PrivilegeEscalationPolicy()
        contract = _make_contract("compute", {IntentCategory.COMPUTATION})
        caps = [_make_capability(CapabilityCategory.SIGNAL_HANDLING, "signal.signal")]
        deviations = policy.evaluate(contract, caps)
        assert len(deviations) == 1
        assert deviations[0].severity == DeviationSeverity.CRITICAL

    def test_no_deviation_when_privilege_intent_declared(self) -> None:
        policy = PrivilegeEscalationPolicy()
        contract = _make_contract("admin_op", {IntentCategory.PRIVILEGE})
        caps = [_make_capability(CapabilityCategory.PRIVILEGE_ESCALATION, "os.chmod")]
        deviations = policy.evaluate(contract, caps)
        assert len(deviations) == 0

    def test_no_deviation_when_subprocess_intent_declared(self) -> None:
        policy = PrivilegeEscalationPolicy()
        contract = _make_contract("run_task", {IntentCategory.SUBPROCESS})
        caps = [_make_capability(CapabilityCategory.PRIVILEGE_ESCALATION, "os.chmod")]
        deviations = policy.evaluate(contract, caps)
        assert len(deviations) == 0


# ---------------------------------------------------------------------------
# CapabilityExpansionPolicy (MG-EXP-001)
# ---------------------------------------------------------------------------


class TestCapabilityExpansionPolicy:
    """Tests for the capability expansion policy."""

    def test_flags_capability_exceeding_intent(self) -> None:
        policy = CapabilityExpansionPolicy()
        contract = _make_contract("read_config", {IntentCategory.FILE_READ})
        caps = [_make_capability(CapabilityCategory.SUBPROCESS, "subprocess.run")]
        deviations = policy.evaluate(contract, caps)
        assert len(deviations) == 1
        assert deviations[0].rule_id == "MG-EXP-001"

    def test_no_deviation_when_intent_matches(self) -> None:
        policy = CapabilityExpansionPolicy()
        contract = _make_contract("run_command", {IntentCategory.SUBPROCESS})
        caps = [_make_capability(CapabilityCategory.SUBPROCESS, "subprocess.run")]
        deviations = policy.evaluate(contract, caps)
        assert len(deviations) == 0

    def test_dynamic_exec_is_critical(self) -> None:
        policy = CapabilityExpansionPolicy()
        contract = _make_contract("compute", {IntentCategory.COMPUTATION})
        caps = [_make_capability(CapabilityCategory.DYNAMIC_EXEC, "eval")]
        deviations = policy.evaluate(contract, caps)
        assert len(deviations) == 1
        assert deviations[0].severity == DeviationSeverity.CRITICAL

    def test_subprocess_is_high(self) -> None:
        policy = CapabilityExpansionPolicy()
        contract = _make_contract("compute", {IntentCategory.COMPUTATION})
        caps = [_make_capability(CapabilityCategory.SUBPROCESS, "subprocess.run")]
        deviations = policy.evaluate(contract, caps)
        assert len(deviations) == 1
        assert deviations[0].severity == DeviationSeverity.HIGH

    def test_file_write_is_medium(self) -> None:
        policy = CapabilityExpansionPolicy()
        contract = _make_contract("compute", {IntentCategory.COMPUTATION})
        caps = [_make_capability(CapabilityCategory.FILE_WRITE, "open('w')")]
        deviations = policy.evaluate(contract, caps)
        assert len(deviations) == 1
        assert deviations[0].severity == DeviationSeverity.MEDIUM

    def test_computation_capability_skipped(self) -> None:
        policy = CapabilityExpansionPolicy()
        contract = _make_contract("compute", {IntentCategory.FILE_READ})
        # COMPUTATION intent is a benign default, should be skipped
        caps = [_make_capability(CapabilityCategory.COMPUTATION, "compute")]
        deviations = policy.evaluate(contract, caps)
        assert len(deviations) == 0

    def test_unknown_capability_skipped(self) -> None:
        policy = CapabilityExpansionPolicy()
        contract = _make_contract("compute", {IntentCategory.FILE_READ})
        caps = [_make_capability(CapabilityCategory.UNKNOWN, "unknown")]
        deviations = policy.evaluate(contract, caps)
        assert len(deviations) == 0


# ---------------------------------------------------------------------------
# PolicyEngine
# ---------------------------------------------------------------------------


class TestPolicyEngine:
    """Tests for the PolicyEngine orchestration."""

    def test_builtin_policies_loaded(self, policy_engine: PolicyEngine) -> None:
        rule_ids = [p.rule_id for p in policy_engine.policies]
        assert "MG-SUB-001" in rule_ids
        assert "MG-FW-001" in rule_ids
        assert "MG-NET-001" in rule_ids
        assert "MG-PRIV-001" in rule_ids
        assert "MG-EXP-001" in rule_ids

    def test_evaluate_returns_deviations(self, policy_engine: PolicyEngine) -> None:
        contract = _make_contract("read_config", {IntentCategory.FILE_READ})
        caps = [_make_capability(CapabilityCategory.SUBPROCESS, "subprocess.run")]
        deviations = policy_engine.evaluate(contract, caps)
        assert len(deviations) >= 1
        rule_ids = {d.rule_id for d in deviations}
        assert "MG-SUB-001" in rule_ids

    def test_evaluate_deduplicates(self, policy_engine: PolicyEngine) -> None:
        contract = _make_contract("compute", {IntentCategory.COMPUTATION})
        caps = [_make_capability(CapabilityCategory.SUBPROCESS, "subprocess.run")]
        deviations = policy_engine.evaluate(contract, caps)
        # Same contract + same capability + same rule_id should be deduplicated
        rule_ids = [d.rule_id for d in deviations]
        # MG-SUB-001 and MG-EXP-001 may both trigger, but each should appear once
        for rule_id in set(rule_ids):
            assert rule_ids.count(rule_id) == 1

    def test_register_custom_policy(self, policy_engine: PolicyEngine) -> None:
        class CustomPolicy(Policy):
            @property
            def rule_id(self) -> str:
                return "MG-CUSTOM-001"

            @property
            def description(self) -> str:
                return "Custom test policy"

            def evaluate(self, contract, capabilities):
                return []

        custom = CustomPolicy()
        initial_count = len(policy_engine.policies)
        policy_engine.register(custom)
        assert len(policy_engine.policies) == initial_count + 1

    def test_register_duplicate_rule_id_raises(self, policy_engine: PolicyEngine) -> None:
        class DuplicatePolicy(Policy):
            @property
            def rule_id(self) -> str:
                return "MG-SUB-001"  # Already exists

            @property
            def description(self) -> str:
                return "Duplicate"

            def evaluate(self, contract, capabilities):
                return []

        with pytest.raises(PolicyError):
            policy_engine.register(DuplicatePolicy())

    def test_unregister_policy(self, policy_engine: PolicyEngine) -> None:
        initial_count = len(policy_engine.policies)
        policy_engine.unregister("MG-SUB-001")
        assert len(policy_engine.policies) == initial_count - 1
        rule_ids = [p.rule_id for p in policy_engine.policies]
        assert "MG-SUB-001" not in rule_ids

    def test_list_policies(self, policy_engine: PolicyEngine) -> None:
        policies = policy_engine.list_policies()
        assert len(policies) >= 5
        assert all("rule_id" in p and "description" in p for p in policies)

    def test_load_custom_policies_from_directory(self, policy_engine: PolicyEngine) -> None:
        with tempfile.TemporaryDirectory() as td:
            policy_file = Path(td) / "custom_policy.py"
            policy_file.write_text('''
from mythguardai.policies.policy_engine import Policy

class TestCustomPolicy(Policy):
    @property
    def rule_id(self):
        return "MG-TEST-001"

    @property
    def description(self):
        return "Test custom policy"

    def evaluate(self, contract, capabilities):
        return []
''')
            policy_engine.load_custom_policies(td)
            rule_ids = [p.rule_id for p in policy_engine.policies]
            assert "MG-TEST-001" in rule_ids

    def test_load_custom_policies_nonexistent_dir_raises(self, policy_engine: PolicyEngine) -> None:
        with pytest.raises(PolicyError):
            policy_engine.load_custom_policies("/nonexistent/path")

    def test_load_custom_policies_file_not_dir_raises(self, policy_engine: PolicyEngine) -> None:
        with tempfile.NamedTemporaryFile(suffix=".py") as tf:
            with pytest.raises(PolicyError):
                policy_engine.load_custom_policies(tf.name)


# ---------------------------------------------------------------------------
# Deterministic replay
# ---------------------------------------------------------------------------


class TestDeterministicReplay:
    """Tests for deterministic replay: same input = same output."""

    def test_same_input_same_output(self) -> None:
        engine = PolicyEngine()
        contract = _make_contract("read_data", {IntentCategory.FILE_READ})
        caps = [
            _make_capability(CapabilityCategory.SUBPROCESS, "subprocess.run"),
            _make_capability(CapabilityCategory.NETWORK_CLIENT, "requests.get"),
        ]
        deviations1 = engine.evaluate(contract, caps)
        deviations2 = engine.evaluate(contract, caps)
        assert len(deviations1) == len(deviations2)
        for d1, d2 in zip(deviations1, deviations2):
            assert d1.rule_id == d2.rule_id
            assert d1.severity == d2.severity
            assert d1.message == d2.message

    def test_different_input_different_output(self) -> None:
        engine = PolicyEngine()
        contract_read = _make_contract("read_data", {IntentCategory.FILE_READ})
        contract_sub = _make_contract("run_cmd", {IntentCategory.SUBPROCESS})
        caps = [_make_capability(CapabilityCategory.SUBPROCESS, "subprocess.run")]
        devs_read = engine.evaluate(contract_read, caps)
        devs_sub = engine.evaluate(contract_sub, caps)
        assert len(devs_read) > len(devs_sub)


# ---------------------------------------------------------------------------
# Severity threshold filtering
# ---------------------------------------------------------------------------


class TestSeverityThresholdFiltering:
    """Tests for severity threshold filtering via ScanResult."""

    def test_filter_by_high_threshold(self) -> None:
        from mythguardai.models import ScanResult

        deviations = [
            Deviation(severity=DeviationSeverity.CRITICAL, rule_id="MG-PRIV-001"),
            Deviation(severity=DeviationSeverity.HIGH, rule_id="MG-SUB-001"),
            Deviation(severity=DeviationSeverity.MEDIUM, rule_id="MG-FW-001"),
            Deviation(severity=DeviationSeverity.LOW, rule_id="MG-EXP-001"),
        ]
        result = ScanResult(deviations=deviations)
        filtered = result.filter_by_severity(DeviationSeverity.HIGH)
        assert len(filtered) == 2
        assert all(d.severity >= DeviationSeverity.HIGH for d in filtered)

    def test_filter_by_critical_threshold(self) -> None:
        from mythguardai.models import ScanResult

        deviations = [
            Deviation(severity=DeviationSeverity.CRITICAL, rule_id="MG-PRIV-001"),
            Deviation(severity=DeviationSeverity.HIGH, rule_id="MG-SUB-001"),
        ]
        result = ScanResult(deviations=deviations)
        filtered = result.filter_by_severity(DeviationSeverity.CRITICAL)
        assert len(filtered) == 1
        assert filtered[0].severity == DeviationSeverity.CRITICAL


# ---------------------------------------------------------------------------
# Policy violation IDs
# ---------------------------------------------------------------------------


class TestPolicyViolationIDs:
    """Tests for specific policy violation rule IDs."""

    def test_mg_sub_001(self) -> None:
        policy = SubprocessExecutionPolicy()
        assert policy.rule_id == "MG-SUB-001"

    def test_mg_fw_001(self) -> None:
        policy = FileWritePolicy()
        assert policy.rule_id == "MG-FW-001"

    def test_mg_net_001(self) -> None:
        policy = NetworkAccessPolicy()
        assert policy.rule_id == "MG-NET-001"

    def test_mg_priv_001(self) -> None:
        policy = PrivilegeEscalationPolicy()
        assert policy.rule_id == "MG-PRIV-001"

    def test_mg_exp_001(self) -> None:
        policy = CapabilityExpansionPolicy()
        assert policy.rule_id == "MG-EXP-001"
