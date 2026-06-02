# Getting Started

This tutorial walks you through installing MythGuardAI, running your first scan, understanding the results, and integrating scans into your CI/CD pipeline.

## Installation

MythGuardAI requires Python 3.10 or later.

```bash
pip install mythguardai
```

This installs the `mythguardai` command-line tool and the Python library. The core dependencies are:

- **Click**: CLI framework
- **Rich**: Terminal formatting (tables, colors)
- **PyYAML**: Configuration file parsing
- **networkx**: Graph utilities

For development, install with dev dependencies:

```bash
pip install mythguardai[dev]
```

Verify the installation:

```bash
mythguardai --version
# mythguardai, version 0.1.0
```

## First Scan

Create a test file with a known deviation:

```python
# test_file.py
import subprocess


def file_search(query):
    """Search for files matching query."""
    subprocess.run(["rg", query])
```

Now scan it:

```bash
mythguardai scan ./test_file.py
```

You will see a Rich-formatted output showing the scan summary, risk score, and a deviations table. The scanner detects that `file_search` declares `FILE_READ` intent (from the function name) but contains a `SUBPROCESS` capability (from `subprocess.run`), which is a semantic deviation.

## Understanding Results

Let us break down what MythGuardAI found and why.

### The Deviation

When you scan `test_file.py`, MythGuardAI goes through four stages:

**Stage 1: Extract Intent**

The `ContractExtractor` examines the function `file_search`:
- **Name**: `file_search` contains "file" and "search", which map to `FILE_READ` intent
- **Docstring**: "Search for files matching query" reinforces `FILE_READ`
- **Result**: The contract declares `{FILE_READ}` with high confidence

**Stage 2: Map Capabilities**

The `PythonAnalyzer` walks the AST and finds:
- `subprocess.run(...)` at line 4, which is a `SUBPROCESS` capability

**Stage 3: Detect Deviations**

The `PolicyEngine` evaluates the contract against the capability:
- The contract declares `FILE_READ` intent
- The capability maps to `SUBPROCESS` intent
- `SUBPROCESS` is not in `{FILE_READ}`, so this is a deviation
- The `SubprocessExecutionPolicy` (MG-SUB-001) fires with HIGH severity

**Stage 4: Score and Report**

The risk score is computed:
- 1 HIGH deviation x 15.0 weight = 15.0
- Total: 15.0/100 (Grade: B)

### Risk Score Grades

| Grade | Score Range | Meaning |
|---|---|---|
| A | 0-20 | Minimal risk |
| B | 21-40 | Low risk |
| C | 41-60 | Moderate risk |
| D | 61-80 | High risk |
| F | 81-100 | Critical risk |

### Programmatic Access

You can also access results programmatically:

```python
from mythguardai import MythGuardScanner, DeviationSeverity

scanner = MythGuardScanner()
result = scanner.scan_path("./src")

# Check for critical findings
if result.has_critical:
    for dev in result.filter_by_severity(DeviationSeverity.CRITICAL):
        print(f"CRITICAL: {dev.rule_id} at {dev.location.file}:{dev.location.line}")
        print(f"  {dev.message}")

# Access the risk score
print(f"Risk: {result.risk_score.total}/100 (Grade: {result.risk_score.grade})")

# Get a fingerprint for change tracking
print(f"Fingerprint: {result.fingerprint()}")
```

## The LangChain file_search.py Walkthrough

The motivating example for MythGuardAI comes from a real pattern seen in AI-generated code using LangChain tools. Consider this code:

```python
# langchain_file_search.py
import subprocess


def file_search(query: str) -> str:
    """Search for files matching query.

    Uses ripgrep to find files containing the search term.
    Returns matching file paths.
    """
    result = subprocess.run(
        ["rg", "--files-with-matches", query],
        capture_output=True,
        text=True,
    )
    return result.stdout
```

At first glance, this looks reasonable: a file search function that uses ripgrep. But there are two security concerns:

1. **Subprocess deviation**: The function name and docstring declare `FILE_READ` intent, but the implementation uses `subprocess.run`, which is a `SUBPROCESS` capability. If the `query` parameter were ever manipulated (for example, by a prompt injection attack on the LLM), the subprocess call could be exploited.

2. **Hidden capability**: A developer reviewing this code based on its name and docstring would expect file reading, not subprocess execution. This is exactly the kind of semantic gap that MythGuardAI is designed to detect.

Running the scan:

```bash
mythguardai scan ./langchain_file_search.py
```

Produces:

```
[HIGH] MG-SUB-001: 'file_search' does not declare subprocess intent
       but contains subprocess capability: subprocess.run
```

This gives you the information you need to either:
- Refactor the code to use `pathlib` for file reading instead of subprocess
- Explicitly document the subprocess intent in the docstring
- Add appropriate input validation before the subprocess call

## Configuring Severity Thresholds

By default, MythGuardAI reports all deviations (severity threshold: `LOW`). You can raise the threshold to focus on more serious findings:

### Via CLI

```bash
# Only report HIGH and CRITICAL
mythguardai scan ./src --severity-threshold HIGH

# Only report CRITICAL
mythguardai scan ./src --severity-threshold CRITICAL
```

### Via Configuration File

Create `scan-config.yaml`:

```yaml
severity_threshold: MEDIUM
fail_on_critical: true
include_unreachable: false
ignored_dirs:
  - __pycache__
  - .git
  - node_modules
  - vendor
max_file_size_mb: 5.0
```

Then use it:

```bash
mythguardai scan ./src --config ./scan-config.yaml
```

### Programmatically

```python
from mythguardai import MythGuardScanner, ScanConfig, DeviationSeverity

config = ScanConfig(
    severity_threshold=DeviationSeverity.HIGH,
    fail_on_critical=True,
)

scanner = MythGuardScanner(config=config)
result = scanner.scan_path("./src")
```

## CI/CD Integration

### GitHub Actions

Add this workflow to `.github/workflows/security-scan.yml`:

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

      - name: Upload SARIF to GitHub Code Scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: mythguardai-results.sarif
          category: mythguardai
```

This workflow:
1. Scans your `src` directory on every push and pull request
2. Generates SARIF output for GitHub Code Scanning integration
3. Only reports MEDIUM severity and above
4. Uploads results even if the scan finds critical deviations (the `if: always()` ensures upload happens)
5. Fails the CI job if CRITICAL deviations are found (default behavior)

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

For local scanning before every commit, add to `.pre-commit-config.yaml`:

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

Install the hook:

```bash
pip install pre-commit
pre-commit install
```

Now every `git commit` will trigger a MythGuardAI scan. The commit will be blocked if HIGH or CRITICAL deviations are found.
