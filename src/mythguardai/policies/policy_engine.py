"""Deterministic policy engine for MythGuardAI.

Evaluates semantic contracts against discovered capabilities and
produces ``Deviation`` instances when capability exceeds intent.

All evaluations are deterministic: the same inputs always produce the
same outputs, making every scan fully auditable and replayable.

Built-in policies:
- SubprocessExecutionPolicy: flag subprocess calls in non-execution contexts
- FileWritePolicy: flag writes in read-only declared contexts
- NetworkAccessPolicy: flag network calls in non-network contexts
- PrivilegeEscalationPolicy: flag privilege operations
- CapabilityExpansionPolicy: flag capabilities exceeding declared intent
"""

from __future__ import annotations

import importlib
import importlib.util
import sys
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Protocol

from mythguardai.exceptions import PolicyError
from mythguardai.models import (
    CAPABILITY_TO_INTENT,
    Capability,
    CapabilityCategory,
    Deviation,
    DeviationSeverity,
    IntentCategory,
    ReachabilityStatus,
    SemanticContract,
)


# ---------------------------------------------------------------------------
# Policy protocol / base class
# ---------------------------------------------------------------------------


class Policy(ABC):
    """Abstract base class for all MythGuardAI policies.

    A policy receives a semantic contract and a set of capabilities
    belonging to the same code unit, and returns zero or more
    deviations. Each deviation must be fully deterministic: the
    same (contract, capabilities) pair always yields the same result.
    """

    @property
    @abstractmethod
    def rule_id(self) -> str:
        """Unique identifier for this policy rule (e.g. 'MG-SUB-001')."""
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable description of what this policy checks."""
        ...

    @abstractmethod
    def evaluate(
        self,
        contract: SemanticContract,
        capabilities: list[Capability],
    ) -> list[Deviation]:
        """Evaluate a contract against capabilities.

        Args:
            contract: The semantic contract to check.
            capabilities: Capabilities discovered in the same code unit.

        Returns:
            A list of deviations found by this policy.
        """
        ...


# ---------------------------------------------------------------------------
# Built-in policies
# ---------------------------------------------------------------------------


class SubprocessExecutionPolicy(Policy):
    """Flag subprocess calls in non-execution contexts.

    A code unit that declares no SUBPROCESS or DYNAMIC_EXEC intent
    but contains subprocess invocations is deviating.

    Severity: HIGH (subprocess access is a strong signal of capability drift).
    """

    @property
    def rule_id(self) -> str:
        return "MG-SUB-001"

    @property
    def description(self) -> str:
        return "Subprocess execution in non-execution context"

    def evaluate(
        self,
        contract: SemanticContract,
        capabilities: list[Capability],
    ) -> list[Deviation]:
        deviations: list[Deviation] = []

        allowed_intents = {
            IntentCategory.SUBPROCESS,
            IntentCategory.DYNAMIC_EXEC,
            IntentCategory.PRIVILEGE,
        }

        if contract.declared_intents & allowed_intents:
            return deviations

        for cap in capabilities:
            if cap.category == CapabilityCategory.SUBPROCESS:
                deviations.append(
                    Deviation(
                        contract=contract,
                        capability=cap,
                        severity=DeviationSeverity.HIGH,
                        rule_id=self.rule_id,
                        message=(
                            f"'{contract.name}' does not declare subprocess intent "
                            f"but contains subprocess capability: {cap.evidence}"
                        ),
                        reachability=cap.reachability,
                        location=cap.location,
                    )
                )

        return deviations


class FileWritePolicy(Policy):
    """Flag file writes in read-only declared contexts.

    A code unit that declares only FILE_READ intent but contains
    FILE_WRITE or TEMP_FILE capabilities is deviating.

    Severity: MEDIUM (data integrity risk).
    """

    @property
    def rule_id(self) -> str:
        return "MG-FW-001"

    @property
    def description(self) -> str:
        return "File write in read-only context"

    def evaluate(
        self,
        contract: SemanticContract,
        capabilities: list[Capability],
    ) -> list[Deviation]:
        deviations: list[Deviation] = []

        write_intents = {
            IntentCategory.FILE_WRITE,
            IntentCategory.PRIVILEGE,
            IntentCategory.SUBPROCESS,
        }

        # If the contract declares write intent, no deviation
        if contract.declared_intents & write_intents:
            return deviations

        # Only flag if the contract has FILE_READ intent but not FILE_WRITE
        has_read_intent = IntentCategory.FILE_READ in contract.declared_intents

        write_categories = {
            CapabilityCategory.FILE_WRITE,
            CapabilityCategory.TEMP_FILE,
            CapabilityCategory.FILE_SYSTEM_MANIPULATION,
        }

        for cap in capabilities:
            if cap.category in write_categories:
                severity = DeviationSeverity.MEDIUM
                if has_read_intent:
                    severity = DeviationSeverity.HIGH

                deviations.append(
                    Deviation(
                        contract=contract,
                        capability=cap,
                        severity=severity,
                        rule_id=self.rule_id,
                        message=(
                            f"'{contract.name}' declares read-only intent "
                            f"but contains file write capability: {cap.evidence}"
                        ),
                        reachability=cap.reachability,
                        location=cap.location,
                    )
                )

        return deviations


class NetworkAccessPolicy(Policy):
    """Flag network calls in non-network contexts.

    A code unit that declares no NETWORK intent but contains
    network capabilities (client or server) is deviating.

    Severity: HIGH (exfiltration and C2 risk).
    """

    @property
    def rule_id(self) -> str:
        return "MG-NET-001"

    @property
    def description(self) -> str:
        return "Network access in non-network context"

    def evaluate(
        self,
        contract: SemanticContract,
        capabilities: list[Capability],
    ) -> list[Deviation]:
        deviations: list[Deviation] = []

        if IntentCategory.NETWORK in contract.declared_intents:
            return deviations

        network_categories = {
            CapabilityCategory.NETWORK_CLIENT,
            CapabilityCategory.NETWORK_SERVER,
        }

        for cap in capabilities:
            if cap.category in network_categories:
                severity = DeviationSeverity.HIGH
                if cap.category == CapabilityCategory.NETWORK_SERVER:
                    severity = DeviationSeverity.CRITICAL

                deviations.append(
                    Deviation(
                        contract=contract,
                        capability=cap,
                        severity=severity,
                        rule_id=self.rule_id,
                        message=(
                            f"'{contract.name}' does not declare network intent "
                            f"but contains network capability: {cap.evidence}"
                        ),
                        reachability=cap.reachability,
                        location=cap.location,
                    )
                )

        return deviations


class PrivilegeEscalationPolicy(Policy):
    """Flag privilege operations in non-privileged contexts.

    A code unit that declares no PRIVILEGE intent but contains
    privilege escalation or signal handling capabilities is deviating.

    Severity: CRITICAL (privilege escalation is a critical security risk).
    """

    @property
    def rule_id(self) -> str:
        return "MG-PRIV-001"

    @property
    def description(self) -> str:
        return "Privilege escalation in non-privileged context"

    def evaluate(
        self,
        contract: SemanticContract,
        capabilities: list[Capability],
    ) -> list[Deviation]:
        deviations: list[Deviation] = []

        privilege_intents = {
            IntentCategory.PRIVILEGE,
            IntentCategory.SUBPROCESS,
        }

        if contract.declared_intents & privilege_intents:
            return deviations

        privilege_categories = {
            CapabilityCategory.PRIVILEGE_ESCALATION,
            CapabilityCategory.SIGNAL_HANDLING,
        }

        for cap in capabilities:
            if cap.category in privilege_categories:
                deviations.append(
                    Deviation(
                        contract=contract,
                        capability=cap,
                        severity=DeviationSeverity.CRITICAL,
                        rule_id=self.rule_id,
                        message=(
                            f"'{contract.name}' does not declare privilege intent "
                            f"but contains privilege capability: {cap.evidence}"
                        ),
                        reachability=cap.reachability,
                        location=cap.location,
                    )
                )

        return deviations


class CapabilityExpansionPolicy(Policy):
    """Flag capabilities that exceed the declared intent of a code unit.

    This is the broadest policy: it checks every discovered capability
    against the contract's declared intents. If a capability maps to an
    intent category not present in the contract, a deviation is raised.

    Severity depends on the capability category:
    - DYNAMIC_EXEC: CRITICAL
    - PRIVILEGE_ESCALATION, NETWORK_SERVER: CRITICAL
    - SUBPROCESS, NETWORK_CLIENT: HIGH
    - FILE_WRITE, ENVIRONMENT_WRITE: MEDIUM
    - Others: LOW
    """

    # Severity mapping for capability categories
    _SEVERITY_MAP: dict[CapabilityCategory, DeviationSeverity] = {
        CapabilityCategory.DYNAMIC_EXEC: DeviationSeverity.CRITICAL,
        CapabilityCategory.PRIVILEGE_ESCALATION: DeviationSeverity.CRITICAL,
        CapabilityCategory.NETWORK_SERVER: DeviationSeverity.CRITICAL,
        CapabilityCategory.SUBPROCESS: DeviationSeverity.HIGH,
        CapabilityCategory.NETWORK_CLIENT: DeviationSeverity.HIGH,
        CapabilityCategory.FILE_WRITE: DeviationSeverity.MEDIUM,
        CapabilityCategory.ENVIRONMENT_WRITE: DeviationSeverity.MEDIUM,
        CapabilityCategory.FILE_SYSTEM_MANIPULATION: DeviationSeverity.MEDIUM,
        CapabilityCategory.TEMP_FILE: DeviationSeverity.LOW,
        CapabilityCategory.FILE_READ: DeviationSeverity.LOW,
        CapabilityCategory.ENVIRONMENT_READ: DeviationSeverity.LOW,
        CapabilityCategory.NETWORK_CLIENT: DeviationSeverity.HIGH,
        CapabilityCategory.SERIALIZATION: DeviationSeverity.LOW,
        CapabilityCategory.CRYPTO: DeviationSeverity.LOW,
        CapabilityCategory.DATABASE: DeviationSeverity.MEDIUM,
        CapabilityCategory.SIGNAL_HANDLING: DeviationSeverity.HIGH,
        CapabilityCategory.MODULE_IMPORT: DeviationSeverity.LOW,
        CapabilityCategory.COMPUTATION: DeviationSeverity.LOW,
        CapabilityCategory.PARSING: DeviationSeverity.LOW,
        CapabilityCategory.UNKNOWN: DeviationSeverity.LOW,
    }

    @property
    def rule_id(self) -> str:
        return "MG-EXP-001"

    @property
    def description(self) -> str:
        return "Capability exceeds declared intent"

    def evaluate(
        self,
        contract: SemanticContract,
        capabilities: list[Capability],
    ) -> list[Deviation]:
        deviations: list[Deviation] = []

        for cap in capabilities:
            intent = cap.intent_category

            # If the capability's intent category is in the contract, no deviation
            if intent in contract.declared_intents:
                continue

            # COMPUTATION and UNKNOWN are benign defaults, skip them
            if intent in {IntentCategory.COMPUTATION, IntentCategory.UNKNOWN}:
                continue

            severity = self._SEVERITY_MAP.get(
                cap.category, DeviationSeverity.MEDIUM
            )

            deviations.append(
                Deviation(
                    contract=contract,
                    capability=cap,
                    severity=severity,
                    rule_id=self.rule_id,
                    message=(
                        f"'{contract.name}' does not declare {intent.value} intent "
                        f"but contains {cap.category.value} capability: {cap.evidence}"
                    ),
                    reachability=cap.reachability,
                    location=cap.location,
                )
            )

        return deviations


# ---------------------------------------------------------------------------
# Policy engine
# ---------------------------------------------------------------------------


class PolicyEngine:
    """Deterministic policy evaluation engine.

    Evaluates semantic contracts against discovered capabilities
    using a set of registered policies. All evaluations are
    deterministic and replayable.

    Usage::

        engine = PolicyEngine()
        deviations = engine.evaluate(contract, capabilities)
    """

    def __init__(self) -> None:
        self._policies: list[Policy] = [
            SubprocessExecutionPolicy(),
            FileWritePolicy(),
            NetworkAccessPolicy(),
            PrivilegeEscalationPolicy(),
            CapabilityExpansionPolicy(),
        ]

    @property
    def policies(self) -> list[Policy]:
        """Return the list of active policies."""
        return list(self._policies)

    def register(self, policy: Policy) -> None:
        """Register a custom policy.

        Args:
            policy: The policy to add.

        Raises:
            PolicyError: If a policy with the same rule_id already exists.
        """
        existing_ids = {p.rule_id for p in self._policies}
        if policy.rule_id in existing_ids:
            raise PolicyError(
                f"Policy with rule_id '{policy.rule_id}' already registered",
                policy_name=policy.rule_id,
            )
        self._policies.append(policy)

    def unregister(self, rule_id: str) -> None:
        """Remove a policy by its rule_id.

        Args:
            rule_id: The rule ID of the policy to remove.
        """
        self._policies = [p for p in self._policies if p.rule_id != rule_id]

    def evaluate(
        self,
        contract: SemanticContract,
        capabilities: list[Capability],
    ) -> list[Deviation]:
        """Evaluate a contract against capabilities using all policies.

        Args:
            contract: The semantic contract to check.
            capabilities: Capabilities discovered in the same code unit.

        Returns:
            A deduplicated list of deviations from all policies.
        """
        deviations: list[Deviation] = []

        for policy in self._policies:
            try:
                new_devs = policy.evaluate(contract, capabilities)
                deviations.extend(new_devs)
            except Exception as exc:
                raise PolicyError(
                    f"Policy {policy.rule_id} failed: {exc}",
                    policy_name=policy.rule_id,
                ) from exc

        # Deduplicate: same contract + same capability + same rule_id
        seen: set[tuple[str, str, str]] = set()
        unique: list[Deviation] = []
        for dev in deviations:
            cap_id = dev.capability.evidence if dev.capability else ""
            key = (dev.rule_id, cap_id, dev.contract.name if dev.contract else "")
            if key not in seen:
                seen.add(key)
                unique.append(dev)

        return unique

    def load_custom_policies(self, policy_dir: str | Path) -> None:
        """Load custom policy modules from a directory.

        Each Python file in the directory should define one or more
        ``Policy`` subclasses. They are instantiated and registered
        with the engine.

        Args:
            policy_dir: Path to the directory containing policy modules.

        Raises:
            PolicyError: If the directory cannot be read or a policy
                module fails to load.
        """
        dir_path = Path(policy_dir)

        if not dir_path.exists():
            raise PolicyError(
                f"Policy directory not found: {dir_path}",
                policy_name=str(dir_path),
            )

        if not dir_path.is_dir():
            raise PolicyError(
                f"Policy path is not a directory: {dir_path}",
                policy_name=str(dir_path),
            )

        for py_file in sorted(dir_path.glob("*.py")):
            if py_file.name.startswith("_"):
                continue

            module_name = f"mythguard_custom_policy_{py_file.stem}"

            try:
                spec = importlib.util.spec_from_file_location(
                    module_name, str(py_file)
                )
                if spec is None or spec.loader is None:
                    raise PolicyError(
                        f"Cannot create module spec for: {py_file}",
                        policy_name=str(py_file),
                    )

                module = importlib.util.module_from_spec(spec)
                sys.modules[module_name] = module
                spec.loader.exec_module(module)  # type: ignore[union-attr]

                # Find Policy subclasses in the module
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if (
                        isinstance(attr, type)
                        and issubclass(attr, Policy)
                        and attr is not Policy
                    ):
                        try:
                            instance = attr()
                            self.register(instance)
                        except Exception as exc:
                            raise PolicyError(
                                f"Cannot instantiate policy {attr_name} "
                                f"from {py_file}: {exc}",
                                policy_name=attr_name,
                            ) from exc

            except PolicyError:
                raise
            except Exception as exc:
                raise PolicyError(
                    f"Failed to load policy module {py_file}: {exc}",
                    policy_name=str(py_file),
                ) from exc

    def list_policies(self) -> list[dict[str, str]]:
        """List all registered policies with their rule IDs and descriptions.

        Returns:
            A list of dictionaries with ``rule_id`` and ``description`` keys.
        """
        return [
            {"rule_id": p.rule_id, "description": p.description}
            for p in self._policies
        ]
