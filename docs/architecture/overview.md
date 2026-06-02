# Architecture Overview

MythGuardAI is a static analysis tool that detects **capability drift** in code by comparing what a code unit *declares* it will do against what it *can actually do*. This document describes the core model, the four-stage analysis pipeline, the component architecture, and the key design guarantees.

## The Semantic Deviation Model

Traditional SAST tools look for dangerous function calls in isolation. MythGuardAI takes a fundamentally different approach: a security failure is not merely the presence of a dangerous call, but the **divergence between declared intent and reachable capability**.

Consider a function named `file_search` with the docstring "Search for files matching query." If that function contains `subprocess.run(rip_grep_cmd)`, the intent is file reading but the capability is subprocess execution. That gap is the deviation.

This model is particularly effective at catching AI-generated code that appears benign on the surface but hides dangerous capabilities behind misleading names and docstrings.

## The Semantic Security Triad

Every scan revolves around three concepts:

| Concept | What it captures | Source |
|---|---|---|
| **Intent** | What the code unit claims to do | Function names, docstrings, type hints, decorators, imports |
| **Capability** | What the code can actually do | AST analysis of function calls, imports, attribute accesses |
| **Reachability** | Whether the capability can be reached from an entry point | Control-flow heuristics at the module and function level |

A **deviation** occurs when a reachable capability maps to an intent category not present in the declared intent of the enclosing code unit. The severity of a deviation depends on the nature of the excess capability:

- `DYNAMIC_EXEC`, `PRIVILEGE_ESCALATION`, `NETWORK_SERVER` produce CRITICAL deviations
- `SUBPROCESS`, `NETWORK_CLIENT` produce HIGH deviations
- `FILE_WRITE`, `ENVIRONMENT_WRITE` produce MEDIUM deviations
- Other categories produce LOW deviations

### Intent Categories

Intent is derived from multiple signals in the source code:

```
FILE_READ       FILE_WRITE      NETWORK         SUBPROCESS
PRIVILEGE       COMPUTATION     PARSING         SERIALIZATION
CRYPTO          DATABASE        ENVIRONMENT     DYNAMIC_EXEC
UNKNOWN
```

### Capability Categories

Capabilities are more fine-grained than intents, reflecting the actual operations the code can perform:

```
FILE_READ               FILE_WRITE              NETWORK_CLIENT
NETWORK_SERVER          SUBPROCESS              PRIVILEGE_ESCALATION
COMPUTATION             PARSING                 SERIALIZATION
CRYPTO                  DATABASE                ENVIRONMENT_READ
ENVIRONMENT_WRITE       DYNAMIC_EXEC            FILE_SYSTEM_MANIPULATION
MODULE_IMPORT           SIGNAL_HANDLING         TEMP_FILE
UNKNOWN
```

Each `CapabilityCategory` maps to an `IntentCategory` via the `CAPABILITY_TO_INTENT` dictionary. For example, `NETWORK_CLIENT` and `NETWORK_SERVER` both map to `IntentCategory.NETWORK`, but they carry different default severities when deviating.

## Four-Stage Pipeline

MythGuardAI processes code through a deterministic four-stage pipeline:

### Stage 1: Extract Intent

The `ContractExtractor` parses the source code and produces a `SemanticContract` for each named code unit (functions, classes, and the module itself). Intent is inferred from four signal sources, in order of strength:

1. **Names**: Function and class names are split on separators and matched against keyword maps. `file_search` yields `FILE_READ`; `send_notification` yields `NETWORK`.
2. **Docstrings**: The raw docstring text is scanned for capability-signaling keywords. "Search for files" reinforces `FILE_READ`; "execute command" adds `SUBPROCESS`.
3. **Type annotations**: Type hints like `Path`, `HttpResponse`, or `CompletedProcess` contribute intent signals.
4. **Decorators**: Route decorators (`@app.route`), authentication decorators (`@login_required`), and task decorators (`@celery.task`) all contribute to the intent set.

If no signals are found, the contract defaults to `COMPUTATION` with reduced confidence.

### Stage 2: Map Capabilities

Language-specific analyzers walk the AST (Python) or apply regex patterns (JavaScript) to discover what the code can actually do. Each call to a known dangerous function, each import of a sensitive module, and each attribute access to a capability-bearing path produces a `Capability` instance with:

- The capability category (e.g., `SUBPROCESS`, `NETWORK_CLIENT`)
- A human-readable description
- The evidence string (e.g., `subprocess.run`, `requests.post`)
- The source location (file, line, column)
- A confidence score

### Stage 3: Detect Deviations

The `PolicyEngine` evaluates each `SemanticContract` against the `Capability` instances discovered in the same code unit. Each registered policy checks for a specific pattern of capability drift:

- **SubprocessExecutionPolicy**: flags `SUBPROCESS` capabilities in contracts that lack `SUBPROCESS` or `DYNAMIC_EXEC` intent
- **FileWritePolicy**: flags `FILE_WRITE` capabilities in contracts that lack `FILE_WRITE` intent
- **NetworkAccessPolicy**: flags `NETWORK_CLIENT` or `NETWORK_SERVER` capabilities in contracts that lack `NETWORK` intent
- **PrivilegeEscalationPolicy**: flags `PRIVILEGE_ESCALATION` capabilities in contracts that lack `PRIVILEGE` intent
- **CapabilityExpansionPolicy**: the broadest check, flags any capability whose mapped intent category is absent from the contract

Deviations are deduplicated by `(rule_id, capability evidence, contract name)` to avoid reporting the same finding multiple times.

Additionally, capabilities that fall outside any contract's source range are reported as **orphan capabilities** (rule `MG-ORPHAN-001`), which may indicate dead code, missing documentation, or intentionally hidden functionality.

### Stage 4: Score and Report

Deviations are aggregated into a composite `RiskScore`:

```
total = min(100, sum(weight * count_for_severity))
```

| Severity | Weight |
|---|---|
| CRITICAL | 25.0 |
| HIGH | 15.0 |
| MEDIUM | 7.0 |
| LOW | 2.0 |

The total maps to a letter grade:

| Grade | Score Range | Risk Level |
|---|---|---|
| A | 0-20 | Minimal |
| B | 21-40 | Low |
| C | 41-60 | Moderate |
| D | 61-80 | High |
| F | 81-100 | Critical |

## Component Diagram

```
+-------------------+     +---------------------+     +-------------------+
|                   |     |                     |     |                   |
|  MythGuardScanner |---->| ContractExtractor   |---->| Python Analyzer   |
|  (orchestrator)   |     | (intent extraction) |     | (AST walker)      |
|                   |     |                     |     +-------------------+
+-------------------+     +---------------------+     |                   |
         |                |                     |---->| JavaScript Analyzer|
         |                +---------------------+     | (regex matcher)   |
         |                                            +-------------------+
         |
         |                +---------------------+
         +--------------->|   PolicyEngine      |
                          |   (deviation detect)|----> [SubprocessExecutionPolicy]
                          |                     |----> [FileWritePolicy]
                          +---------------------+----> [NetworkAccessPolicy]
                                  |             |----> [PrivilegeEscalationPolicy]
                                  |             |----> [CapabilityExpansionPolicy]
                                  |             |----> [Custom policies...]
                                  v
                          +---------------------+
                          |   Reporters         |
                          +---------------------+----> [JsonReporter]
                                                  ----> [MarkdownReporter]
                                                  ----> [SarifReporter]
```

## Data Flow

1. **Input**: Source code (file path, directory, or raw string) enters the `MythGuardScanner`.
2. **Contract Extraction**: The `ContractExtractor` parses the code and produces a list of `SemanticContract` objects, each with a set of `IntentCategory` values and a confidence score.
3. **Capability Mapping**: The appropriate language analyzer produces a list of `Capability` objects with category, evidence, location, and confidence.
4. **Deviation Detection**: The `PolicyEngine` evaluates each contract against its matching capabilities, producing `Deviation` objects. Orphan capabilities are also reported.
5. **Reachability Computation**: Each deviation is annotated with a `ReachabilityStatus` (`REACHABLE`, `CONDITIONAL`, or `UNREACHABLE`) based on control-flow heuristics.
6. **Filtering**: Deviations below the configured severity threshold are removed. Unreachable deviations are optionally excluded.
7. **Scoring**: The `RiskScore` is computed from the filtered deviation list.
8. **Reporting**: A reporter serializes the `ScanResult` into the requested format (JSON, Markdown, or SARIF).

All intermediate data structures (contracts, capabilities, deviations) are plain dataclasses with deterministic serialization via `to_dict()` / `from_dict()`.

## Determinism Guarantees

MythGuardAI is designed for full determinism: **the same source code, scanned with the same configuration, always produces the same results**. This is achieved through:

- **No randomness**: No random sampling, probabilistic heuristics, or non-deterministic orderings are used anywhere in the pipeline.
- **Deterministic serialization**: All models use `to_dict()` with consistent key ordering. Deviation IDs are derived from UUID4 but are fixed once created.
- **Stable ordering**: File walks use `sorted()`, policy evaluation iterates policies in registration order, and deviations are deduplicated deterministically.
- **Fingerprinting**: The `ScanResult.fingerprint()` method computes a SHA-256 hash over the sorted deviation set (by rule_id, severity, capability category, and reachability), enabling exact comparison between two scans without relying on scan_id or timestamp.
- **No network calls**: The scanner never contacts external services. All analysis is local.

## Offline Capability

MythGuardAI operates entirely offline:

- No API keys, no network calls, no telemetry, no phone-home.
- All pattern databases, capability signatures, and intent maps are embedded in the source code.
- The only external dependency is the Python standard library (plus Click, Rich, and PyYAML for CLI and configuration).
- Custom policies are loaded from local files, not from remote registries.

This makes MythGuardAI suitable for air-gapped environments, classified networks, and any context where data must not leave the premises.

## Auditability and Replayability

Every scan produces a `ScanResult` that is fully serializable and replayable:

- **Full context**: Each `Deviation` carries both the `SemanticContract` and the `Capability` that triggered it, so you can see exactly why a finding was raised without re-running the scan.
- **Configuration snapshot**: The `ScanResult.metadata` field includes the scanner version and the full configuration used, so you can reproduce the exact scan conditions.
- **Fingerprint comparison**: Two scans of the same code with the same configuration will produce the same fingerprint. If the fingerprint differs, the findings differ.
- **Round-trip serialization**: `ScanResult.to_dict()` and `ScanResult.from_dict()` enable full round-trip through JSON, supporting archival, diffing, and automated comparison across CI runs.
- **Timestamp**: Each scan records its UTC timestamp, enabling temporal analysis of scan results over time.
