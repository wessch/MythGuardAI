# Reporter API

MythGuardAI provides three built-in reporters for different use cases, and supports custom reporter authoring for specialized output formats.

## Built-in Reporters

### JsonReporter

Formats scan results as structured JSON, suitable for programmatic consumption, piping to `jq`, or archival.

```python
from mythguardai import JsonReporter, ScanResult

reporter = JsonReporter()
json_string = reporter.render(result)
print(json_string)

# Write to file
reporter.render_to_file(result, "scan-results.json")
```

#### Methods

| Method | Signature | Description |
|---|---|---|
| `render` | `render(result: ScanResult, *, indent: int = 2) -> str` | Render as a JSON string |
| `render_to_file` | `render_to_file(result: ScanResult, path: str, *, indent: int = 2) -> None` | Write to a JSON file |

#### Output Structure

The JSON output is a direct serialization of `ScanResult.to_dict()`:

```json
{
  "scan_id": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
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
        "type_annotations": {},
        "decorators": [],
        "location": {
          "file": "./src/search.py",
          "line": 1,
          "col": 0,
          "end_line": 4,
          "end_col": 30
        },
        "confidence": 1.0,
        "metadata": {}
      },
      "capability": {
        "category": "SUBPROCESS",
        "description": "Subprocess execution via subprocess.run",
        "evidence": "subprocess.run",
        "location": {
          "file": "./src/search.py",
          "line": 3,
          "col": 4,
          "end_line": 3,
          "end_col": 22
        },
        "reachability": "REACHABLE",
        "confidence": 0.9,
        "metadata": {}
      },
      "severity": "HIGH",
      "rule_id": "MG-SUB-001",
      "message": "'file_search' does not declare subprocess intent but contains subprocess capability: subprocess.run",
      "reachability": "REACHABLE",
      "location": {
        "file": "./src/search.py",
        "line": 3,
        "col": 4,
        "end_line": 3,
        "end_col": 22
      },
      "metadata": {}
    }
  ],
  "contracts": [...],
  "capabilities": [...],
  "risk_score": {
    "total": 15.0,
    "grade": "B",
    "critical_count": 0,
    "high_count": 1,
    "medium_count": 0,
    "low_count": 0
  },
  "duration_ms": 42.5,
  "metadata": {
    "scanner_version": "0.1.0",
    "config": {...}
  },
  "fingerprint": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}
```

#### Piping to jq

```bash
mythguardai scan ./src --format json | jq '.risk_score'
mythguardai scan ./src --format json | jq '.deviations[] | select(.severity == "CRITICAL")'
mythguardai scan ./src --format json | jq '.deviations | length'
```

### MarkdownReporter

Formats scan results as a human-readable Markdown document, suitable for documentation, code review comments, or CI artifacts.

```python
from mythguardai import MarkdownReporter, ScanResult

reporter = MarkdownReporter()
markdown_string = reporter.render(result)
print(markdown_string)

# Write to file
reporter.render_to_file(result, "security-report.md")
```

#### Methods

| Method | Signature | Description |
|---|---|---|
| `render` | `render(result: ScanResult) -> str` | Render as a Markdown string |
| `render_to_file` | `render_to_file(result: ScanResult, path: str) -> None` | Write to a Markdown file |

#### Output Structure

The Markdown report contains these sections:

1. **Header**: Title and scan metadata
2. **Executive Summary**: Target, scan ID, timestamp, duration, deviation count, risk score
3. **Risk Breakdown**: Table of severity counts
4. **Fingerprint**: SHA-256 hash for scan comparison
5. **Deviations**: Grouped by severity (CRITICAL first), each with rule ID, message, contract, capability, location, and reachability
6. **Semantic Contracts**: Table of all extracted contracts with declared intents and confidence
7. **Discovered Capabilities**: Table of all capabilities with category, evidence, location, and reachability

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

Fingerprint: `e3b0c44298fc1c14...`

## Deviations

### :large_orange_diamond: HIGH (1)

**[MG-SUB-001]** 'file_search' does not declare subprocess intent but contains subprocess capability: subprocess.run

- Contract: `file_search`
- Capability: `subprocess.run`
- Location: ./src/search.py:3
- Reachability: REACHABLE

## Semantic Contracts

| Name | Declared Intents | Confidence |
|------|-----------------|------------|
| `file_search` | FILE_READ | 100% |

## Discovered Capabilities

| Category | Evidence | Location | Reachability |
|----------|----------|----------|--------------|
| SUBPROCESS | `subprocess.run` | ./src/search.py:3 | REACHABLE |
```

### SarifReporter

Formats scan results as SARIF v2.1.0, the Static Analysis Results Interchange Format used by GitHub Code Scanning, Azure DevOps, and other security tooling platforms.

```python
from mythguardai import SarifReporter, ScanResult

reporter = SarifReporter()
sarif_string = reporter.render(result)
print(sarif_string)

# Write to file
reporter.render_to_file(result, "results.sarif")
```

#### Methods

| Method | Signature | Description |
|---|---|---|
| `render` | `render(result: ScanResult, *, indent: int = 2) -> str` | Render as a SARIF JSON string |
| `render_to_file` | `render_to_file(result: ScanResult, path: str, *, indent: int = 2) -> None` | Write to a SARIF file |

#### Severity Mapping

MythGuardAI severity levels map to SARIF levels and ranks as follows:

| MythGuardAI Severity | SARIF Level | SARIF Rank |
|---|---|---|
| CRITICAL | `error` | 90.0 |
| HIGH | `error` | 70.0 |
| MEDIUM | `warning` | 50.0 |
| LOW | `note` | 20.0 |

#### Output Structure

The SARIF document follows the v2.1.0 specification:

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
          "semanticVersion": "0.1.0",
          "informationUri": "https://github.com/wessch/MythGuardAI",
          "rules": [
            {
              "id": "MG-SUB-001",
              "name": "MG-SUB-001",
              "shortDescription": {
                "text": "Subprocess execution in non-execution context"
              },
              "fullDescription": {
                "text": "A code unit that does not declare subprocess or dynamic execution intent was found to contain subprocess capability..."
              },
              "helpUri": "https://github.com/wessch/MythGuardAI/blob/main/docs/rules/MG-SUB-001.md",
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
                  "startLine": 3,
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
      ],
      "invocations": [
        {
          "executionSuccessful": true,
          "startTimeUtc": "2025-01-15T10:30:00+00:00"
        }
      ],
      "properties": {
        "scanId": "a1b2c3d4e5f6",
        "target": "./src",
        "riskScore": {
          "total": 15.0,
          "grade": "B",
          "critical_count": 0,
          "high_count": 1,
          "medium_count": 0,
          "low_count": 0
        },
        "fingerprint": "e3b0c44298fc1c14...",
        "durationMs": 42.5
      }
    }
  ]
}
```

#### Uploading to GitHub Code Scanning

```bash
# Generate SARIF output
mythguardai scan ./src --format sarif --output results.sarif

# Upload using GitHub CLI
gh api /repos/:owner/:repo/code-scanning/sarifs \
  -f commit_sha="$GITHUB_SHA" \
  -f ref="$GITHUB_REF" \
  --input results.sarif
```

Or use the `github/codeql-action/upload-sarif` action (see the CLI reference for a full GitHub Actions example).

## Custom Reporter Authoring

You can create custom reporters for specialized output formats (HTML, Slack messages, JUnit XML, etc.).

### Reporter Interface

A custom reporter should implement at least a `render()` method that takes a `ScanResult` and returns a string. There is no formal base class required, but following the same interface as the built-in reporters ensures compatibility:

```python
from mythguardai import ScanResult


class HtmlReporter:
    """Formats scan results as an HTML page."""

    def render(self, result: ScanResult) -> str:
        """Render a scan result as an HTML string."""
        sections = []

        # HTML header
        sections.append("<!DOCTYPE html>")
        sections.append("<html><head>")
        sections.append("<title>MythGuardAI Report</title>")
        sections.append("<style>")
        sections.append("body { font-family: sans-serif; margin: 2em; }")
        sections.append(".critical { color: #dc3545; font-weight: bold; }")
        sections.append(".high { color: #fd7e14; font-weight: bold; }")
        sections.append(".medium { color: #ffc107; }")
        sections.append(".low { color: #0d6efd; }")
        sections.append("table { border-collapse: collapse; width: 100%; }")
        sections.append("th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }")
        sections.append("</style>")
        sections.append("</head><body>")

        # Summary
        score = result.risk_score
        sections.append(f"<h1>MythGuardAI Security Report</h1>")
        sections.append(f"<p>Target: <code>{result.target}</code></p>")
        sections.append(f"<p>Risk Score: {score.total}/100 (Grade: {score.grade})</p>")

        # Deviations table
        if result.deviations:
            sections.append("<h2>Deviations</h2>")
            sections.append("<table>")
            sections.append("<tr><th>Rule</th><th>Severity</th><th>Message</th><th>Location</th></tr>")
            for dev in result.deviations:
                severity_class = dev.severity.value.lower()
                location = f"{dev.location.file}:{dev.location.line}" if dev.location else "N/A"
                sections.append(
                    f"<tr>"
                    f"<td>{dev.rule_id}</td>"
                    f"<td class='{severity_class}'>{dev.severity.value}</td>"
                    f"<td>{dev.message}</td>"
                    f"<td>{location}</td>"
                    f"</tr>"
                )
            sections.append("</table>")
        else:
            sections.append("<p>No deviations found.</p>")

        sections.append("</body></html>")
        return "\n".join(sections)

    def render_to_file(self, result: ScanResult, path: str) -> None:
        """Write the report to a file."""
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.render(result))
```

### Using a Custom Reporter

```python
from mythguardai import MythGuardScanner
from my_reporters import HtmlReporter

scanner = MythGuardScanner()
result = scanner.scan_path("./src")

reporter = HtmlReporter()
reporter.render_to_file(result, "security-report.html")
```

### Tips for Custom Reporters

1. **Access all data**: The `ScanResult` contains `deviations`, `contracts`, `capabilities`, `risk_score`, and `metadata`. Use whatever you need.
2. **Use the severity enum**: `dev.severity.value` gives you the string ("CRITICAL", "HIGH", etc.) for display.
3. **Handle missing data gracefully**: `dev.location`, `dev.contract`, and `dev.capability` may be `None` in edge cases (orphan deviations have `contract=None`).
4. **Keep it deterministic**: Like everything else in MythGuardAI, reporters should produce the same output for the same input.
