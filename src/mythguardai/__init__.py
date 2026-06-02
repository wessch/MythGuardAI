"""MythGuardAI: Semantic Application Security for the AI Era.

Compare declared intent vs reachable capability to find semantic
deviations. Deterministic, offline-capable, fully auditable.

The triad: Intent -> Capability -> Reachability
Security failure = divergence between declared intent and reachable capability

GitHub: https://github.com/wessch/MythGuardAI
Author: Wesley Schouw

Quick start::

    from mythguardai import MythGuardScanner, ScanConfig

    scanner = MythGuardScanner()
    result = scanner.scan_path("./src")

    for dev in result.deviations:
        print(f"[{dev.severity.value}] {dev.rule_id}: {dev.message}")

    print(f"Risk score: {result.risk_score.total}/100 (Grade: {result.risk_score.grade})")
"""

__version__ = "0.1.0"
__author__ = "Wesley Schouw"
__project__ = "MythGuardAI"

# Core models
from mythguardai.models import (
    Capability,
    CapabilityCategory,
    CAPABILITY_TO_INTENT,
    Deviation,
    DeviationSeverity,
    IntentCategory,
    ReachabilityStatus,
    RiskScore,
    ScanResult,
    SemanticContract,
    SourceLocation,
)

# Engine
from mythguardai.engine import ContractExtractor, MythGuardScanner

# Configuration
from mythguardai.config import ScanConfig, default_config, load_config

# Exceptions
from mythguardai.exceptions import (
    AnalyzerError,
    ConfigurationError,
    MythGuardError,
    PolicyError,
    ScanError,
)

# Policies
from mythguardai.policies.policy_engine import (
    CapabilityExpansionPolicy,
    FileWritePolicy,
    NetworkAccessPolicy,
    Policy,
    PolicyEngine,
    PrivilegeEscalationPolicy,
    SubprocessExecutionPolicy,
)

# Reporters
from mythguardai.reporters import JsonReporter, MarkdownReporter, SarifReporter

__all__ = [
    # Version
    "__version__",
    "__author__",
    "__project__",
    # Core models
    "Capability",
    "CapabilityCategory",
    "CAPABILITY_TO_INTENT",
    "Deviation",
    "DeviationSeverity",
    "IntentCategory",
    "ReachabilityStatus",
    "RiskScore",
    "ScanResult",
    "SemanticContract",
    "SourceLocation",
    # Engine
    "ContractExtractor",
    "MythGuardScanner",
    # Configuration
    "ScanConfig",
    "default_config",
    "load_config",
    # Exceptions
    "AnalyzerError",
    "ConfigurationError",
    "MythGuardError",
    "PolicyError",
    "ScanError",
    # Policies
    "CapabilityExpansionPolicy",
    "FileWritePolicy",
    "NetworkAccessPolicy",
    "Policy",
    "PolicyEngine",
    "PrivilegeEscalationPolicy",
    "SubprocessExecutionPolicy",
    # Reporters
    "JsonReporter",
    "MarkdownReporter",
    "SarifReporter",
]
