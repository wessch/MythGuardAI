# MythGuardAI

**Semantic Application Security for the AI Era**

[![PyPI](https://img.shields.io/pypi/v/mythguardai?color=blue&label=PyPI)](https://pypi.org/project/mythguardai/)
[![Python](https://img.shields.io/pypi/pyversions/mythguardai?label=Python)](https://pypi.org/project/mythguardai/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/wessch/MythGuardAI/actions/workflows/ci.yml/badge.svg)](https://github.com/wessch/MythGuardAI/actions/workflows/ci.yml)

> Security failure is not a bug. It is a divergence between declared intent and reachable capability.

MythGuardAI detects hidden capability drift in code before it reaches production. It compares what code claims to do against what it can actually do, surfacing semantic deviations where code "lies" about its behavior. It is deterministic, offline-capable, and fully auditable.

Traditional security tools check whether code is broken. MythGuardAI checks whether code is honest.

---

## Why MythGuardAI?

In the age of AI-generated code, the threat is no longer just bugs. It is **deception**. A function that declares it "reads a config file" but also reaches network sockets, environment variables, and subprocess execution is not buggy. It is semantically malicious, and no linter will catch it.

MythGuardAI was built to close this gap. It answers a question no other tool asks:

**Does this code do only what it says it does?**

---

## Key Features

| Feature | Description |
|---|---|
| **Deterministic** | Same input, same output. No probabilistic heuristics, no false confidence. Every finding is traceable to a concrete code path. |
| **Offline** | No telemetry, no cloud calls, no API keys. Runs entirely on your infrastructure. Your code never leaves your machine. |
| **Auditable** | Every decision is backed by a traceable evidence chain. You can inspect, verify, and reproduce every finding. |
| **CI/CD Integration** | Drop-in pipeline support. Fail builds on semantic drift, not just syntax errors. |
| **Semantic Drift Detection** | Tracks divergence between declared intent and reachable capability over time. Catch creeping privilege expansion before it becomes an incident. |
| **AI-Generated Code Verification** | Purpose-built to audit LLM-generated code for hidden capability that was not part of the prompt. |

---

## The Semantic Security Triad

MythGuardAI operates on three axes that form the Semantic Security Triad:

```
Intent          Capability          Reachability
"What was       "What               "What can be
 promised?"      exists?"            activated?"
     |                |                    |
     v                v                    v
 Declarations,    Imports, functions,   Call graphs, data flow,
 annotations,     classes, modules      execution paths
 docstrings
```

1. **Intent**: What was promised? Extracted from declarations, annotations, docstrings, package metadata, and README files.
2. **Capability**: What exists? Discovered through static analysis of imports, function definitions, class hierarchies, and module structure.
3. **Reachability**: What can be activated? Computed via call graph traversal, data flow analysis, and execution path enumeration.

A **semantic deviation** occurs when reachable capability exceeds declared intent. This is the signal MythGuardAI detects.

---

## Quick Start

### Installation

```bash
pip install mythguardai
```

For optional AST pattern matching with tree-sitter:

```bash
pip install mythguardai[ast-grep]
```

### Usage

Scan a project directory:

```bash
mythguardai scan ./my-project
```

Scan with a specific trust contract:

```bash
mythguardai scan ./my-project --contract trust-contract.yaml
```

Generate a semantic drift report:

```bash
mythguardai drift ./my-project --baseline previous-scan.json
```

Output formats:

```bash
mythguardai scan ./my-project --format json    # machine-readable
mythguardai scan ./my-project --format sarif   # GitHub Advanced Security
mythguardai scan ./my-project --format rich    # terminal-friendly (default)
```

---

## Architecture

```
mythguardai/
  cli.py              # Command-line interface (click + rich)
  scanner/
    intent.py         # Intent extraction from declarations and metadata
    capability.py     # Capability discovery via static analysis
    reachability.py   # Reachability computation via call graph traversal
    drift.py          # Semantic drift detection and scoring
  contract/
    loader.py         # Trust contract parsing and validation
    validator.py      # Contract enforcement against scan results
  report/
    formatter.py      # Output formatting (JSON, SARIF, Rich)
    evidence.py       # Evidence chain construction for findings
  models/
    finding.py        # Finding data models
    contract.py       # Trust contract data models
    metrics.py        # Quantifiable metric models
```

---

## MythGuardAI vs. Traditional SAST

| Dimension | Traditional SAST | MythGuardAI |
|---|---|---|
| **Core question** | "Is this code broken?" | "Is this code honest?" |
| **Detection model** | Pattern matching on known vuln signatures | Semantic gap analysis between intent and capability |
| **False positive strategy** | Suppress via tuning rules | Minimize via reachability verification |
| **AI-generated code** | Treats like human code (same patterns) | Audits for hidden capability not in the prompt |
| **Drift detection** | None (point-in-time scans only) | Tracks semantic deviation across commits and releases |
| **Determinism** | Often heuristic-based | Fully deterministic, every finding is traceable |
| **Offline support** | Varies, many require cloud connectivity | Fully offline, zero telemetry |
| **Auditability** | Rule-based reports | Evidence chain for every finding, reproducible |
| **Output** | Vulnerability list | Intent/capability/reachability divergence with metrics |

---

## MythGuardAI + Mythos

MythGuardAI is the **defender's instrument**. It analyzes code from the builder's perspective, ensuring declared intent matches reachable capability.

**Mythos** is the companion system that operates from the **attacker's perspective**. It probes the same triad but asks a different question: "How can I make this code do what it was never intended to do?"

Together, they form a complete adversarial loop:

- **MythGuardAI**: "Does this code stay within its declared boundaries?"
- **Mythos**: "Can I push this code beyond its declared boundaries?"

Mythos is not public. It informs MythGuardAI's detection capabilities by continuously testing the boundaries of semantic analysis.

---

## Quantifiable Metrics

MythGuardAI produces concrete, reproducible metrics for every scan:

### Semantic Drift Score (SDS)

Measures the aggregate divergence between declared intent and reachable capability on a 0-100 scale.

- **0**: Code does exactly what it declares.
- **100**: No meaningful relationship between intent and capability.

Formula: `SDS = (unintended_reachable_capabilities / total_reachable_capabilities) * 100`

### Capability Expansion Index (CEI)

Tracks how the capability surface grows over time relative to declared intent. A rising CEI indicates creeping privilege expansion.

Formula: `CEI = (new_capabilities - newly_declared_capabilities) / baseline_capabilities`

### Reachability Score (RS)

The fraction of discovered capabilities that are actually reachable through execution paths. Distinguishes theoretical risk from practical risk.

Formula: `RS = reachable_capabilities / total_discovered_capabilities`

### Trust Contract Violations (TCV)

Count of explicit violations against a defined trust contract. Each violation links to a specific contract clause and the code path that breaches it.

### Behavioral Entropy

Measures the unpredictability of code behavior relative to declared intent. Higher entropy means the code's actual behavior is less predictable from its declarations.

Formula: `H = -sum(p_i * log2(p_i))` where `p_i` is the probability of each behavioral category given the declared intent.

---

## Commercial Roadmap

### Phase 1: Foundation (Current)
- Core semantic analysis engine
- Intent/capability/reachability triad implementation
- CLI and basic reporting
- Open-source under MIT license

### Phase 2: Integration
- CI/CD pipeline plugins (GitHub Actions, GitLab CI, Jenkins)
- SARIF output for GitHub Advanced Security
- Trust contract schema standardization
- Language server protocol support

### Phase 3: Scale
- Multi-language support beyond Python
- Monorepo and microservice architecture scanning
- Historical drift tracking across repositories
- Team-level dashboards and trend analysis

### Phase 4: Enterprise
- Policy engine with organizational trust contracts
- Compliance mapping (SOC 2, ISO 27001, NIST)
- Role-based access and audit log management
- On-premise deployment with enterprise support

### Phase 5: Adversarial Loop
- Mythos-informed detection pattern updates
- Automated red-team/blue-team semantic analysis
- Real-time semantic monitoring for production systems
- Custom adversarial scenario generation

---

## Contributing

We welcome contributions. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines, development setup, and submission process.

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

Copyright (c) 2026 Wesley Schouw
