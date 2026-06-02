# Policy Engine

The policy engine is the core decision-making component of MythGuardAI. It evaluates semantic contracts against discovered capabilities and produces deviations when capability exceeds declared intent. This document covers how policies work, the built-in policies, custom policy authoring, and configuration.

## How Policies Are Evaluated

Policy evaluation is **deterministic and replayable**: the same inputs always produce the same outputs. There is no randomness, no machine learning, and no external state involved.

The evaluation flow:

1. The `PolicyEngine` receives a `SemanticContract` and a list of `Capability` instances belonging to the same code unit.
2. Each registered policy is invoked in registration order via its `evaluate()` method.
3. Each policy independently checks for its specific deviation pattern and returns zero or more `Deviation` instances.
4. The engine deduplicates results by `(rule_id, capability evidence, contract name)` to avoid reporting the same finding multiple times from overlapping policies.
5. If any policy raises an exception, it is wrapped in a `PolicyError` and propagated.

```python
from mythguardai import PolicyEngine, SemanticContract, Capability

engine = PolicyEngine()
deviations = engine.evaluate(contract, capabilities)

for dev in deviations:
    print(f"[{dev.severity.value}] {dev.rule_id}: {dev.message}")
```

## Built-in Policies

| Rule ID | Policy Name | Description | Default Severity |
|---|---|---|---|
| `MG-SUB-001` | SubprocessExecutionPolicy | Flags subprocess calls in code units that do not declare `SUBPROCESS`, `DYNAMIC_EXEC`, or `PRIVILEGE` intent | HIGH |
| `MG-FW-001` | FileWritePolicy | Flags file write, temp file, or file system manipulation capabilities in code units that do not declare `FILE_WRITE`, `PRIVILEGE`, or `SUBPROCESS` intent. Escalates to HIGH when the contract declares `FILE_READ` only | MEDIUM (or HIGH if read-only) |
| `MG-NET-001` | NetworkAccessPolicy | Flags network client or server capabilities in code units that do not declare `NETWORK` intent. `NETWORK_SERVER` escalates to CRITICAL | HIGH (or CRITICAL for server) |
| `MG-PRIV-001` | PrivilegeEscalationPolicy | Flags privilege escalation or signal handling capabilities in code units that do not declare `PRIVILEGE` or `SUBPROCESS` intent | CRITICAL |
| `MG-EXP-001` | CapabilityExpansionPolicy | Flags any capability whose mapped intent category is not present in the contract's declared intents (excluding `COMPUTATION` and `UNKNOWN`). Severity varies by capability category | Varies |
| `MG-ORPHAN-001` | Orphan detection | Flags capabilities that fall outside any contract's source range, potentially indicating hidden or undocumented functionality | MEDIUM |

### Severity Breakdown by Capability

The `CapabilityExpansionPolicy` assigns severity based on the capability category:

| Capability Category | Default Severity |
|---|---|
| `DYNAMIC_EXEC` | CRITICAL |
| `PRIVILEGE_ESCALATION` | CRITICAL |
| `NETWORK_SERVER` | CRITICAL |
| `SUBPROCESS` | HIGH |
| `NETWORK_CLIENT` | HIGH |
| `SIGNAL_HANDLING` | HIGH |
| `FILE_WRITE` | MEDIUM |
| `ENVIRONMENT_WRITE` | MEDIUM |
| `FILE_SYSTEM_MANIPULATION` | MEDIUM |
| `DATABASE` | MEDIUM |
| `TEMP_FILE` | LOW |
| `FILE_READ` | LOW |
| `ENVIRONMENT_READ` | LOW |
| `SERIALIZATION` | LOW |
| `CRYPTO` | LOW |
| `MODULE_IMPORT` | LOW |
| `COMPUTATION` | LOW |
| `PARSING` | LOW |

## Custom Policy Authoring

You can extend MythGuardAI by writing custom policies. A custom policy is a Python class that inherits from `mythguardai.Policy` and implements three things:

1. The `rule_id` property: a unique identifier (e.g., `"MG-CUSTOM-001"`)
2. The `description` property: a human-readable description
3. The `evaluate()` method: the logic that checks a contract against capabilities

### Policy Class Structure

```python
from mythguardai import (
    Policy,
    SemanticContract,
    Capability,
    Deviation,
    DeviationSeverity,
    CapabilityCategory,
    IntentCategory,
)


class DataExfiltrationPolicy(Policy):
    """Flag environment variable reads combined with network access."""

    @property
    def rule_id(self) -> str:
        return "MG-CUSTOM-EXFIL-001"

    @property
    def description(self) -> str:
        return "Potential data exfiltration: environment read + network access"

    def evaluate(
        self,
        contract: SemanticContract,
        capabilities: list[Capability],
    ) -> list[Deviation]:
        deviations: list[Deviation] = []

        # If the contract declares NETWORK intent, skip
        if IntentCategory.NETWORK in contract.declared_intents:
            return deviations

        # Check for environment read AND network capability in the same unit
        has_env_read = any(
            cap.category == CapabilityCategory.ENVIRONMENT_READ
            for cap in capabilities
        )
        network_caps = [
            cap for cap in capabilities
            if cap.category in {
                CapabilityCategory.NETWORK_CLIENT,
                CapabilityCategory.NETWORK_SERVER,
            }
        ]

        if has_env_read and network_caps:
            for net_cap in network_caps:
                deviations.append(
                    Deviation(
                        contract=contract,
                        capability=net_cap,
                        severity=DeviationSeverity.CRITICAL,
                        rule_id=self.rule_id,
                        message=(
                            f"'{contract.name}' reads environment variables "
                            f"and makes network requests, indicating potential "
                            f"data exfiltration: {net_cap.evidence}"
                        ),
                        reachability=net_cap.reachability,
                        location=net_cap.location,
                    )
                )

        return deviations
```

### Key Rules for Custom Policies

1. **Be deterministic**: The same `(contract, capabilities)` pair must always produce the same deviations. Never use `random`, `time`, or external state.
2. **Use unique rule IDs**: Each policy must have a unique `rule_id`. Registering a duplicate raises `PolicyError`.
3. **Return Deviation objects**: Always construct deviations with the `contract`, `capability`, `severity`, `rule_id`, `message`, `reachability`, and `location` fields.
4. **Respect the intent model**: Compare capability categories against the contract's `declared_intents`. A deviation should only fire when a capability maps to an intent not present in the contract.
5. **Keep it focused**: Each policy should check one specific pattern. Multiple policies can fire on the same code unit; the engine handles deduplication.

### Registering Custom Policies

There are two ways to register custom policies:

#### Programmatically

```python
from mythguardai import MythGuardScanner, PolicyEngine
from my_policies import DataExfiltrationPolicy

scanner = MythGuardScanner()
scanner._policy_engine.register(DataExfiltrationPolicy())

result = scanner.scan_path("./src")
```

#### Via Policy Directories

Place your policy files in a directory and point the scanner at it:

```python
from mythguardai import MythGuardScanner, ScanConfig

config = ScanConfig(policy_dirs=["./custom_policies"])
scanner = MythGuardScanner(config=config)

result = scanner.scan_path("./src")
```

Or via the CLI:

```bash
mythguardai policy check ./src --policy-dir ./custom_policies
```

Each Python file in the policy directory is loaded as a module. Any class that inherits from `Policy` and is not `Policy` itself is instantiated and registered. Files starting with `_` are skipped.

## Policy Configuration

### YAML Configuration

Policies can be configured via the scan configuration file. The `severity_threshold` option controls the minimum severity reported:

```yaml
# scan-config.yaml
severity_threshold: MEDIUM        # Only report MEDIUM, HIGH, and CRITICAL
policy_dirs:
  - ./custom_policies
fail_on_critical: true            # Exit with non-zero code on CRITICAL findings
include_unreachable: false        # Exclude UNREACHABLE deviations
```

### Disabling Specific Policies

To disable a built-in policy, unregister it after creating the scanner:

```python
from mythguardai import MythGuardScanner

scanner = MythGuardScanner()
scanner._policy_engine.unregister("MG-EXP-001")  # Remove the broadest policy

result = scanner.scan_path("./src")
```

### Listing Active Policies

```python
from mythguardai import PolicyEngine

engine = PolicyEngine()
for policy_info in engine.list_policies():
    print(f"{policy_info['rule_id']}: {policy_info['description']}")
```

Or via the CLI:

```bash
mythguardai policy list
```

## Severity Thresholds and Advisory Modes

### Severity Thresholds

The `severity_threshold` configuration option filters deviations below the specified level:

| Threshold | Reported Severities |
|---|---|
| `LOW` | LOW, MEDIUM, HIGH, CRITICAL (all findings) |
| `MEDIUM` | MEDIUM, HIGH, CRITICAL |
| `HIGH` | HIGH, CRITICAL |
| `CRITICAL` | CRITICAL only |

This is applied after all policies have evaluated, so it does not affect the risk score computation (which uses all deviations before filtering).

### Advisory Mode

Setting `fail_on_critical: false` puts the scanner in advisory mode: it will report all findings but will not exit with a non-zero code, even when CRITICAL deviations are found. This is useful for:

- Gradual rollout of MythGuardAI in existing codebases
- Informational scans that should not block CI
- Baseline generation before enforcing policies

```yaml
# Advisory mode: report everything, but never fail CI
severity_threshold: LOW
fail_on_critical: false
include_unreachable: true
```

### Strict Mode

For maximum security enforcement:

```yaml
# Strict mode: fail on any HIGH or CRITICAL finding
severity_threshold: HIGH
fail_on_critical: true
include_unreachable: false
```
