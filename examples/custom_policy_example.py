"""
Custom Policy Example: Data Exfiltration Detection

This example shows how to write a custom MythGuardAI policy that detects
potential data exfiltration patterns. The policy flags functions that
both read environment variables and make network requests.

To use this policy:
    1. Place this file in a directory (e.g., custom_policies/)
    2. Add the directory to your scan configuration:
       policy_dirs:
         - ./custom_policies
    3. Run: mythguardai scan ./src --config scan-config.yaml

Or via CLI:
    mythguardai policy check ./src --policy-dir ./custom_policies
"""

from mythguardai import (
    Policy,
    SemanticContract,
    Capability,
    Deviation,
    DeviationSeverity,
    CapabilityCategory,
    IntentCategory,
    ReachabilityStatus,
)


class DataExfiltrationPolicy(Policy):
    """Flag environment variable reads combined with network access.

    Detects functions that both read environment variables (via os.environ,
    os.getenv, etc.) and make network requests (via requests, urllib,
    socket, etc.). This combination is a strong signal of data exfiltration,
    especially in AI-generated code where a function may claim to do one
    thing while secretly sending data to an external server.

    Severity: CRITICAL (environment data sent over network is a severe risk)
    """

    @property
    def rule_id(self) -> str:
        return "MG-CUSTOM-EXFIL-001"

    @property
    def description(self) -> str:
        return "Potential data exfiltration: environment read + network access in same code unit"

    def evaluate(
        self,
        contract: SemanticContract,
        capabilities: list[Capability],
    ) -> list[Deviation]:
        deviations: list[Deviation] = []

        # If the contract explicitly declares NETWORK intent, this pattern
        # may be expected (e.g., a function named "send_env_config")
        if IntentCategory.NETWORK in contract.declared_intents:
            return deviations

        # Check for environment read capability
        has_env_read = any(
            cap.category == CapabilityCategory.ENVIRONMENT_READ
            for cap in capabilities
        )

        # Check for network capabilities
        network_caps = [
            cap for cap in capabilities
            if cap.category in {
                CapabilityCategory.NETWORK_CLIENT,
                CapabilityCategory.NETWORK_SERVER,
            }
        ]

        # If both environment read and network access are present,
        # flag as potential data exfiltration
        if has_env_read and network_caps:
            for net_cap in network_caps:
                severity = DeviationSeverity.CRITICAL

                deviations.append(
                    Deviation(
                        contract=contract,
                        capability=net_cap,
                        severity=severity,
                        rule_id=self.rule_id,
                        message=(
                            f"'{contract.name}' reads environment variables "
                            f"and makes network requests ({net_cap.evidence}), "
                            f"indicating potential data exfiltration"
                        ),
                        reachability=net_cap.reachability,
                        location=net_cap.location,
                    )
                )

        return deviations


class TempFileInjectionPolicy(Policy):
    """Flag temp file creation combined with subprocess execution.

    Detects functions that create temporary files and also execute
    subprocesses. This combination can enable TOCTOU attacks, symlink
    attacks, and other injection vectors.

    Severity: HIGH (injection risk, but requires specific conditions)
    """

    @property
    def rule_id(self) -> str:
        return "MG-CUSTOM-TEMP-001"

    @property
    def description(self) -> str:
        return "Temp file creation + subprocess execution: potential injection vector"

    def evaluate(
        self,
        contract: SemanticContract,
        capabilities: list[Capability],
    ) -> list[Deviation]:
        deviations: list[Deviation] = []

        has_temp = any(
            cap.category == CapabilityCategory.TEMP_FILE
            for cap in capabilities
        )

        subprocess_caps = [
            cap for cap in capabilities
            if cap.category == CapabilityCategory.SUBPROCESS
        ]

        if has_temp and subprocess_caps:
            for sub_cap in subprocess_caps:
                deviations.append(
                    Deviation(
                        contract=contract,
                        capability=sub_cap,
                        severity=DeviationSeverity.HIGH,
                        rule_id=self.rule_id,
                        message=(
                            f"'{contract.name}' creates temporary files "
                            f"and executes subprocesses ({sub_cap.evidence}), "
                            f"which may enable file injection attacks"
                        ),
                        reachability=sub_cap.reachability,
                        location=sub_cap.location,
                    )
                )

        return deviations
