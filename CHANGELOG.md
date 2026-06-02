# Changelog

All notable changes to MythGuardAI will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-03-04

### Added

- Core semantic analysis engine with intent, capability, and reachability triad
- Intent extraction from declarations, annotations, docstrings, and metadata
- Capability discovery via static analysis of imports, functions, and classes
- Reachability computation via call graph traversal and data flow analysis
- Semantic drift detection and scoring (SDS, CEI, RS, TCV, Behavioral Entropy)
- Trust contract parsing, validation, and enforcement
- CLI with scan and drift commands via Click
- Output formatting: JSON, SARIF, and Rich (terminal)
- Evidence chain construction for all findings
- Full offline operation with zero telemetry
- CI/CD integration support
- MIT License

[0.1.0]: https://github.com/wessch/MythGuardAI/releases/tag/v0.1.0
