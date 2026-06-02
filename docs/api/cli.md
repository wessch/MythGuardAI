# CLI Reference

MythGuardAI provides a Click-based command-line interface. Install it with:

```bash
pip install mythguardai
```

The CLI entry point is `mythguardai`.

## Global Options

| Option | Description |
|---|---|
| `--version` | Show the version and exit |
| `--help` | Show help and exit |

## Commands

### scan

Scan a file or directory for capability drift.

```bash
mythguardai scan [OPTIONS] PATH
```

**Arguments:**

| Argument | Required | Description |
|---|---|---|
| `PATH` | Yes | The file or directory to scan |

**Options:**

| Option | Type | Default | Description |
|---|---|---|---|
| `--format` | choice: `json`, `markdown`, `sarif` | `json` | Output format |
| `--severity-threshold` | choice: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` | `LOW` | Minimum severity to report |
| `--output` | path | stdout | Write output to a file |
| `--config` | path | None | Path to a configuration file |

**Examples:**

```bash
# Scan a directory with default settings
mythguardai scan ./src

# Scan and output SARIF for GitHub Code Scanning
mythguardai scan ./src --format sarif --output results.sarif

# Scan with HIGH severity threshold
mythguardai scan ./src --severity-threshold HIGH

# Scan using a configuration file
mythguardai scan ./src --config ./scan-config.yaml
```

### analyze

Analyze a single file and show capabilities.

```bash
mythguardai analyze [OPTIONS] FILE
```

**Arguments:**

| Argument | Required | Description |
|---|---|---|
| `FILE` | Yes | The source file to analyze |

**Options:**

| Option | Type | Default | Description |
|---|---|---|---|
| `--language` | choice: `python`, `javascript` | auto-detected | Language of the file |

**Examples:**

```bash
# Analyze a Python file
mythguardai analyze ./src/handlers.py

# Analyze a TypeScript file with explicit language
mythguardai analyze ./app.ts --language javascript
```

### policy list

List all registered security policies.

```bash
mythguardai policy list
```

**Example output:**

```
Registered Policies
------------------------------------------------------------
  MG-SUB-001: Subprocess execution in non-execution context
  MG-FW-001: File write in read-only context
  MG-NET-001: Network access in non-network context
  MG-PRIV-001: Privilege escalation in non-privileged context
  MG-EXP-001: Capability exceeds declared intent
```

### policy check

Check a path against all registered policies.

```bash
mythguardai policy check [OPTIONS] PATH
```

**Arguments:**

| Argument | Required | Description |
|---|---|---|
| `PATH` | Yes | The file or directory to check |

**Options:**

| Option | Type | Default | Description |
|---|---|---|---|
| `--policy-dir` | path (multiple) | None | Directory containing custom policy modules |

**Examples:**

```bash
# Check with default policies
mythguardai policy check ./src

# Check with custom policies
mythguardai policy check ./src --policy-dir ./custom_policies

# Check with multiple policy directories
mythguardai policy check ./src --policy-dir ./policies --policy-dir ./team_policies
```

## Output Formats

### JSON

The JSON output is a direct serialization of the `ScanResult.to_dict()` structure:

```json
{
  "scan_id": "a1b2c3d4e5f6",
  "target": "./src",
  "timestamp": "2025-01-15T10:30:00+00:00",
  "deviations": [
    {
      "id": "f7a8b9c0d1e2",
      "contract": {
        "name": "file_search",
        "source": "./src/search.py",
        "declared_intents": ["FILE_READ"],
        "docstring": "Search for files matching query.",
        "confidence": 1.0
      },
      "capability": {
        "category": "SUBPROCESS",
        "description": "Subprocess execution via subprocess.run",
        "evidence": "subprocess.run",
        "location": {
          "file": "./src/search.py",
          "line": 4,
          "col": 4
        },
        "reachability": "REACHABLE",
        "confidence": 0.9
      },
      "severity": "HIGH",
      "rule_id": "MG-SUB-001",
      "message": "'file_search' does not declare subprocess intent but contains subprocess capability: subprocess.run",
      "reachability": "REACHABLE",
      "location": {
        "file": "./src/search.py",
        "line": 4,
        "col": 4
      }
    }
  ],
  "risk_score": {
    "total": 15.0,
    "grade": "B",
    "critical_count": 0,
    "high_count": 1,
    "medium_count": 0,
    "low_count": 0
  },
  "duration_ms": 42.5,
  "fingerprint": "sha256hash..."
}
```

### Markdown

The Markdown output provides a human-readable report with an executive summary, risk breakdown table, and detailed deviation listings grouped by severity:

```markdown
# MythGuardAI Security Report

## Executive Summary

- **Target**: `./src`
- **Scan ID**: `a1b2c3d4e5f6`
- **Timestamp**: 2025-01-15T10:30:00+00:00
- **Duration**: 42.5 ms
- **Deviations Found**: 3
- **Risk Score**: 22/100 (Grade: B)

### Risk Breakdown

| Severity | Count |
|----------|-------|
| CRITICAL | 0 |
| HIGH | 1 |
| MEDIUM | 1 |
| LOW | 1 |

## Deviations

### :large_orange_diamond: HIGH (1)

**[MG-SUB-001]** 'file_search' does not declare subprocess intent but contains subprocess capability: subprocess.run

- Contract: `file_search`
- Capability: `subprocess.run`
- Location: ./src/search.py:4
- Reachability: REACHABLE
```

### SARIF v2.1.0

The SARIF output is compatible with GitHub Code Scanning, Azure DevOps, and any tool that consumes the SARIF standard:

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "MythGuardAI",
          "version": "0.1.0",
          "informationUri": "https://github.com/wessch/MythGuardAI",
          "rules": [
            {
              "id": "MG-SUB-001",
              "name": "MG-SUB-001",
              "shortDescription": {
                "text": "Subprocess execution in non-execution context"
              },
              "defaultConfiguration": {
                "level": "error"
              },
              "properties": {
                "tags": ["security", "semantic-drift"]
              }
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "MG-SUB-001",
          "level": "error",
          "rank": 70.0,
          "message": {
            "text": "'file_search' does not declare subprocess intent but contains subprocess capability: subprocess.run"
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "./src/search.py"
                },
                "region": {
                  "startLine": 4,
                  "startColumn": 5
                }
              }
            }
          ],
          "properties": {
            "deviationId": "f7a8b9c0d1e2",
            "severity": "HIGH",
            "reachability": "REACHABLE",
            "contractName": "file_search",
            "capabilityCategory": "SUBPROCESS"
          }
        }
      ]
    }
  ]
}
```

## CI/CD Integration

### GitHub Actions

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

      - name: Run security scan
        run: |
          mythguardai scan ./src \
            --format sarif \
            --output mythguardai-results.sarif \
            --severity-threshold MEDIUM

      - name: Upload SARIF results
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: mythguardai-results.sarif
          category: mythguardai
```

### GitLab CI

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
        --format json
        --output mythguardai-results.json
        --severity-threshold MEDIUM
  artifacts:
    paths:
      - mythguardai-results.json
    reports:
      sast: mythguardai-results.json
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == "main"
```

### Pre-commit Hook

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: mythguardai
        name: MythGuardAI Security Scan
        entry: mythguardai scan
        language: system
        types: [python]
        args: ["--severity-threshold", "HIGH"]
        pass_filenames: false
```

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Scan completed successfully, no CRITICAL findings (or `fail_on_critical` is disabled) |
| `1` | Scan completed but CRITICAL deviations were found and `fail_on_critical` is enabled |
| `2` | A MythGuardAI error occurred (invalid path, configuration error, policy error) |
| `3` | An unexpected error occurred |
