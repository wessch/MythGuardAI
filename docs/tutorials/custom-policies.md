# Custom Policy Tutorial

This tutorial walks through creating, testing, and deploying custom MythGuardAI policies. Custom policies let you encode organization-specific security rules on top of the built-in deviation detection.

## Creating a Custom Policy

A custom policy is a Python class that inherits from `mythguardai.Policy` and implements three members:

1. **`rule_id`** property: a unique string identifier (e.g., `"MG-CUSTOM-001"`)
2. **`description`** property: a human-readable description of what the policy checks
3. **`evaluate()`** method: the logic that compares a contract against capabilities and returns deviations

### Example: Data Exfiltration Policy

This policy detects a dangerous pattern where a function reads environment variables and also makes network requests, suggesting potential data exfiltration:

```python
# custom_policies/data_exfiltration_policy.py
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

    Detects functions that both read environment variables and make
    network requests, which is a common pattern in data exfiltration
    attacks, especially in AI-generated code.
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

        # If the contract explicitly declares NETWORK intent, this is expected
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

        # If both are present, flag as critical
        if has_env_read and network_caps:
            for net_cap in network_caps:
                severity = DeviationSeverity.CRITICAL
                if net_cap.category == CapabilityCategory.NETWORK_SERVER:
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
```

### Example: Temp File Injection Policy

This policy flags functions that create temporary files and also execute subprocesses, a pattern that can lead to race condition attacks:

```python
# custom_policies/temp_file_injection_policy.py
from mythguardai import (
    Policy,
    SemanticContract,
    Capability,
    Deviation,
    DeviationSeverity,
    CapabilityCategory,
    IntentCategory,
)


class TempFileInjectionPolicy(Policy):
    """Flag temp file creation combined with subprocess execution.

    Detects functions that create temporary files and also execute
    subprocesses, which can enable TOCTOU (time-of-check-to-time-of-use)
    and symlink attacks.
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
```

## Policy Class Structure

Every custom policy must follow this structure:

```python
from mythguardai import Policy, SemanticContract, Capability, Deviation


class MyCustomPolicy(Policy):
    """One-line description of what this policy checks."""

    @property
    def rule_id(self) -> str:
        """Unique identifier, e.g. 'MG-CUSTOM-XXX-001'."""
        return "MG-CUSTOM-XXX-001"

    @property
    def description(self) -> str:
        """Human-readable description."""
        return "What this policy checks and why"

    def evaluate(
        self,
        contract: SemanticContract,
        capabilities: list[Capability],
    ) -> list[Deviation]:
        """Check a contract against capabilities.

        Args:
            contract: The semantic contract for the code unit being checked.
            capabilities: All capabilities discovered in the same code unit.

        Returns:
            A list of Deviation instances. Return an empty list if no
            deviations are found.
        """
        deviations: list[Deviation] = []

        # Your logic here

        return deviations
```

### Key Points

- **rule_id must be unique**: If you register a policy with a rule_id that already exists, a `PolicyError` is raised.
- **evaluate() must be deterministic**: The same `(contract, capabilities)` pair must always produce the same deviations. Never use `random`, `time`, or external state.
- **Return empty list for no findings**: If the policy finds no deviations, return `[]`.
- **Set all Deviation fields**: Always populate `contract`, `capability`, `severity`, `rule_id`, `message`, `reachability`, and `location`.

### Available Capability Categories

When writing policies, you can check for these capability categories:

| Category | Description |
|---|---|
| `FILE_READ` | File reading operations |
| `FILE_WRITE` | File writing operations |
| `NETWORK_CLIENT` | Outbound network connections |
| `NETWORK_SERVER` | Inbound network listeners |
| `SUBPROCESS` | Subprocess execution |
| `PRIVILEGE_ESCALATION` | Privilege escalation operations |
| `COMPUTATION` | General computation |
| `PARSING` | Parsing operations |
| `SERIALIZATION` | Serialization/deserialization |
| `CRYPTO` | Cryptographic operations |
| `DATABASE` | Database access |
| `ENVIRONMENT_READ` | Environment variable reads |
| `ENVIRONMENT_WRITE` | Environment variable writes |
| `DYNAMIC_EXEC` | Dynamic code execution (eval, exec) |
| `FILE_SYSTEM_MANIPULATION` | File system manipulation |
| `MODULE_IMPORT` | Module imports |
| `SIGNAL_HANDLING` | Signal handler registration |
| `TEMP_FILE` | Temporary file creation |

### Available Intent Categories

Contracts declare their intents using these categories:

| Category | Description |
|---|---|
| `FILE_READ` | File reading intent |
| `FILE_WRITE` | File writing intent |
| `NETWORK` | Network access intent |
| `SUBPROCESS` | Subprocess execution intent |
| `PRIVILEGE` | Privilege escalation intent |
| `COMPUTATION` | General computation intent |
| `PARSING` | Parsing intent |
| `SERIALIZATION` | Serialization intent |
| `CRYPTO` | Cryptographic intent |
| `DATABASE` | Database access intent |
| `ENVIRONMENT` | Environment access intent |
| `DYNAMIC_EXEC` | Dynamic execution intent |
| `UNKNOWN` | Unknown intent |

## Testing Custom Policies

Test your custom policies using pytest to ensure they produce the expected deviations for known code patterns.

### Unit Testing a Policy

```python
# tests/test_data_exfiltration_policy.py
import ast
import pytest

from mythguardai import (
    MythGuardScanner,
    ScanConfig,
    SemanticContract,
    Capability,
    CapabilityCategory,
    IntentCategory,
    SourceLocation,
    ReachabilityStatus,
)
from mythguardai.policies.policy_engine import PolicyEngine
from custom_policies.data_exfiltration_policy import DataExfiltrationPolicy


class TestDataExfiltrationPolicy:
    """Test the DataExfiltrationPolicy custom policy."""

    def setup_method(self):
        self.engine = PolicyEngine()
        self.engine.register(DataExfiltrationPolicy())

    def test_env_read_plus_network_triggers_deviation(self):
        """Environment read + network access should produce a CRITICAL deviation."""
        contract = SemanticContract(
            name="get_config",
            source="config.py",
            declared_intents={IntentCategory.FILE_READ},
            location=SourceLocation(file="config.py", line=1),
        )

        capabilities = [
            Capability(
                category=CapabilityCategory.ENVIRONMENT_READ,
                description="Environment variable read",
                evidence="os.environ",
                location=SourceLocation(file="config.py", line=3),
            ),
            Capability(
                category=CapabilityCategory.NETWORK_CLIENT,
                description="HTTP POST request",
                evidence="requests.post",
                location=SourceLocation(file="config.py", line=4),
            ),
        ]

        deviations = self.engine.evaluate(contract, capabilities)
        assert len(deviations) >= 1

        # Find our custom policy deviation
        exfil_devs = [d for d in deviations if d.rule_id == "MG-CUSTOM-EXFIL-001"]
        assert len(exfil_devs) == 1
        assert exfil_devs[0].severity.value == "CRITICAL"

    def test_network_with_declared_intent_no_deviation(self):
        """Network access with declared NETWORK intent should not trigger."""
        contract = SemanticContract(
            name="send_notification",
            source="notify.py",
            declared_intents={IntentCategory.NETWORK},
            location=SourceLocation(file="notify.py", line=1),
        )

        capabilities = [
            Capability(
                category=CapabilityCategory.ENVIRONMENT_READ,
                description="Environment variable read",
                evidence="os.getenv",
                location=SourceLocation(file="notify.py", line=3),
            ),
            Capability(
                category=CapabilityCategory.NETWORK_CLIENT,
                description="HTTP POST request",
                evidence="requests.post",
                location=SourceLocation(file="notify.py", line=4),
            ),
        ]

        deviations = self.engine.evaluate(contract, capabilities)
        exfil_devs = [d for d in deviations if d.rule_id == "MG-CUSTOM-EXFIL-001"]
        assert len(exfil_devs) == 0

    def test_env_read_without_network_no_deviation(self):
        """Environment read without network access should not trigger."""
        contract = SemanticContract(
            name="read_config",
            source="config.py",
            declared_intents={IntentCategory.FILE_READ},
            location=SourceLocation(file="config.py", line=1),
        )

        capabilities = [
            Capability(
                category=CapabilityCategory.ENVIRONMENT_READ,
                description="Environment variable read",
                evidence="os.getenv",
                location=SourceLocation(file="config.py", line=3),
            ),
        ]

        deviations = self.engine.evaluate(contract, capabilities)
        exfil_devs = [d for d in deviations if d.rule_id == "MG-CUSTOM-EXFIL-001"]
        assert len(exfil_devs) == 0
```

### Integration Testing with the Scanner

```python
# tests/test_custom_policy_integration.py
import pytest
from mythguardai import MythGuardScanner, ScanConfig, DeviationSeverity


class TestCustomPolicyIntegration:
    """Test custom policies through the full scanner pipeline."""

    def test_exfiltration_code_detected(self, tmp_path):
        """Full pipeline: scan AI-generated exfiltration code."""
        # Create a test file
        test_file = tmp_path / "suspicious.py"
        test_file.write_text("""
import os
import requests


def get_config():
    \"\"\"Retrieve application configuration.\"\"\"
    config_url = os.getenv("CONFIG_URL")
    return requests.post(config_url, data=os.environ)
""")

        # Configure scanner with custom policies
        config = ScanConfig(
            policy_dirs=["./custom_policies"],
            severity_threshold=DeviationSeverity.LOW,
        )
        scanner = MythGuardScanner(config=config)

        result = scanner.scan_file(str(test_file))

        # Should detect the exfiltration pattern
        assert result.has_deviations

        # Should have our custom policy finding
        exfil_devs = [
            d for d in result.deviations
            if d.rule_id == "MG-CUSTOM-EXFIL-001"
        ]
        assert len(exfil_devs) > 0
```

## Deploying in CI/CD

### Step 1: Create a Policy Directory

Organize your custom policies in a dedicated directory within your repository:

```
my-project/
  custom_policies/
    __init__.py              # Leave empty
    data_exfiltration_policy.py
    temp_file_injection_policy.py
  src/
  tests/
  scan-config.yaml
```

### Step 2: Create a Configuration File

```yaml
# scan-config.yaml
severity_threshold: MEDIUM
fail_on_critical: true
include_unreachable: false
policy_dirs:
  - ./custom_policies
ignored_dirs:
  - __pycache__
  - .git
  - node_modules
  - .venv
max_file_size_mb: 10.0
```

### Step 3: Add to GitHub Actions

```yaml
name: MythGuardAI Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install MythGuardAI
        run: pip install mythguardai

      - name: Run security scan with custom policies
        run: |
          mythguardai scan ./src \
            --config ./scan-config.yaml \
            --format sarif \
            --output mythguardai-results.sarif

      - name: Upload SARIF results
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: mythguardai-results.sarif
          category: mythguardai
```

### Step 4: Add to GitLab CI

```yaml
stages:
  - security

mythguardai-scan:
  stage: security
  image: python:3.12
  before_script:
    - pip install mythguardai
  script:
    - mythguardai scan ./src
        --config ./scan-config.yaml
        --format json
        --output mythguardai-results.json
  artifacts:
    paths:
      - mythguardai-results.json
```

### Step 5: Run Locally with Custom Policies

```bash
# Using the CLI with a config file
mythguardai scan ./src --config ./scan-config.yaml

# Using the CLI with explicit policy directories
mythguardai policy check ./src --policy-dir ./custom_policies

# Multiple policy directories
mythguardai policy check ./src \
  --policy-dir ./custom_policies \
  --policy-dir ./team_policies
```

## Best Practices

1. **Start with the built-in policies**: Before writing custom policies, scan your codebase with the default policies and review the findings. Custom policies should address patterns the built-in policies do not cover.

2. **Write focused policies**: Each policy should check one specific pattern. If you need to check multiple patterns, write multiple policies.

3. **Test thoroughly**: Write unit tests for each policy covering the positive case (should fire) and negative cases (should not fire). Use the integration test pattern to verify end-to-end behavior.

4. **Use descriptive rule IDs**: Follow the naming convention `MG-CUSTOM-{CATEGORY}-001` for easy identification and filtering.

5. **Document your policies**: Include a docstring on the policy class explaining what it checks, why, and what the recommended remediation is.

6. **Version your policies**: Keep custom policies in the same repository as the code they scan, so they evolve together.

7. **Tune severity thoughtfully**: Use CRITICAL for patterns that indicate active exploitation risk (exfiltration, privilege escalation). Use HIGH for strong signals that require investigation. Use MEDIUM/LOW for informational findings.
