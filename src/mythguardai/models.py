"""Core data models for MythGuardAI.

The triad: Intent -> Capability -> Reachability.

A *SemanticContract* captures the declared intent of a code unit. A
*Capability* captures what that code can actually do. A *Deviation*
records the mismatch when reachable capability exceeds declared intent.

All models are plain dataclasses with full type annotations and
deterministic serialization via ``to_dict()`` / ``from_dict()``.
"""

from __future__ import annotations

import enum
import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class DeviationSeverity(enum.Enum):
    """Severity levels for detected deviations.

    Ordered from least to most severe so that comparisons like
    ``severity >= DeviationSeverity.HIGH`` behave as expected.
    """

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, DeviationSeverity):
            return NotImplemented
        order = list(DeviationSeverity)
        return order.index(self) >= order.index(other)

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, DeviationSeverity):
            return NotImplemented
        order = list(DeviationSeverity)
        return order.index(self) > order.index(other)

    def __le__(self, other: object) -> bool:
        if not isinstance(other, DeviationSeverity):
            return NotImplemented
        order = list(DeviationSeverity)
        return order.index(self) <= order.index(other)

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, DeviationSeverity):
            return NotImplemented
        order = list(DeviationSeverity)
        return order.index(self) < order.index(other)


class ReachabilityStatus(enum.Enum):
    """How reachable a capability is from the entry point.

    - UNREACHABLE: dead code, no control-flow path reaches it.
    - CONDITIONAL: reachable only under specific runtime conditions.
    - REACHABLE: unconditionally reachable from the entry point.
    """

    UNREACHABLE = "UNREACHABLE"
    CONDITIONAL = "CONDITIONAL"
    REACHABLE = "REACHABLE"


class IntentCategory(enum.Enum):
    """Categories of declared intent derived from code signals.

    Each category maps to a broad class of operations. The policy
    engine compares these against discovered capabilities.
    """

    FILE_READ = "FILE_READ"
    FILE_WRITE = "FILE_WRITE"
    NETWORK = "NETWORK"
    SUBPROCESS = "SUBPROCESS"
    PRIVILEGE = "PRIVILEGE"
    COMPUTATION = "COMPUTATION"
    PARSING = "PARSING"
    SERIALIZATION = "SERIALIZATION"
    CRYPTO = "CRYPTO"
    DATABASE = "DATABASE"
    ENVIRONMENT = "ENVIRONMENT"
    DYNAMIC_EXEC = "DYNAMIC_EXEC"
    UNKNOWN = "UNKNOWN"


class CapabilityCategory(enum.Enum):
    """Categories of discovered capabilities.

    These mirror ``IntentCategory`` values where applicable but also
    include finer-grained distinctions (e.g. NETWORK_SERVER vs.
    NETWORK_CLIENT).
    """

    FILE_READ = "FILE_READ"
    FILE_WRITE = "FILE_WRITE"
    NETWORK_CLIENT = "NETWORK_CLIENT"
    NETWORK_SERVER = "NETWORK_SERVER"
    SUBPROCESS = "SUBPROCESS"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    COMPUTATION = "COMPUTATION"
    PARSING = "PARSING"
    SERIALIZATION = "SERIALIZATION"
    CRYPTO = "CRYPTO"
    DATABASE = "DATABASE"
    ENVIRONMENT_READ = "ENVIRONMENT_READ"
    ENVIRONMENT_WRITE = "ENVIRONMENT_WRITE"
    DYNAMIC_EXEC = "DYNAMIC_EXEC"
    FILE_SYSTEM_MANIPULATION = "FILE_SYSTEM_MANIPULATION"
    MODULE_IMPORT = "MODULE_IMPORT"
    SIGNAL_HANDLING = "SIGNAL_HANDLING"
    TEMP_FILE = "TEMP_FILE"
    UNKNOWN = "UNKNOWN"


# ---------------------------------------------------------------------------
# Mapping: CapabilityCategory -> IntentCategory
# ---------------------------------------------------------------------------

CAPABILITY_TO_INTENT: dict[CapabilityCategory, IntentCategory] = {
    CapabilityCategory.FILE_READ: IntentCategory.FILE_READ,
    CapabilityCategory.FILE_WRITE: IntentCategory.FILE_WRITE,
    CapabilityCategory.NETWORK_CLIENT: IntentCategory.NETWORK,
    CapabilityCategory.NETWORK_SERVER: IntentCategory.NETWORK,
    CapabilityCategory.SUBPROCESS: IntentCategory.SUBPROCESS,
    CapabilityCategory.PRIVILEGE_ESCALATION: IntentCategory.PRIVILEGE,
    CapabilityCategory.COMPUTATION: IntentCategory.COMPUTATION,
    CapabilityCategory.PARSING: IntentCategory.PARSING,
    CapabilityCategory.SERIALIZATION: IntentCategory.SERIALIZATION,
    CapabilityCategory.CRYPTO: IntentCategory.CRYPTO,
    CapabilityCategory.DATABASE: IntentCategory.DATABASE,
    CapabilityCategory.ENVIRONMENT_READ: IntentCategory.ENVIRONMENT,
    CapabilityCategory.ENVIRONMENT_WRITE: IntentCategory.ENVIRONMENT,
    CapabilityCategory.DYNAMIC_EXEC: IntentCategory.DYNAMIC_EXEC,
    CapabilityCategory.FILE_SYSTEM_MANIPULATION: IntentCategory.FILE_WRITE,
    CapabilityCategory.MODULE_IMPORT: IntentCategory.COMPUTATION,
    CapabilityCategory.SIGNAL_HANDLING: IntentCategory.PRIVILEGE,
    CapabilityCategory.TEMP_FILE: IntentCategory.FILE_WRITE,
    CapabilityCategory.UNKNOWN: IntentCategory.UNKNOWN,
}


# ---------------------------------------------------------------------------
# Core Models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SourceLocation:
    """A location within a source file.

    Attributes:
        file: Absolute or relative path to the file.
        line: 1-based line number (0 if unknown).
        col: 0-based column offset (-1 if unknown).
        end_line: Ending line number, inclusive (0 if unknown).
        end_col: Ending column offset, exclusive (-1 if unknown).
    """

    file: str
    line: int = 0
    col: int = -1
    end_line: int = 0
    end_col: int = -1

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dictionary."""
        return {
            "file": self.file,
            "line": self.line,
            "col": self.col,
            "end_line": self.end_line,
            "end_col": self.end_col,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SourceLocation:
        """Deserialize from a plain dictionary."""
        return cls(
            file=data["file"],
            line=data.get("line", 0),
            col=data.get("col", -1),
            end_line=data.get("end_line", 0),
            end_col=data.get("end_col", -1),
        )


@dataclass
class SemanticContract:
    """The declared intent of a code unit.

    A contract captures what a function, class, or module *claims* to
    do, derived from its name, docstring, type hints, decorators, and
    naming conventions.

    Attributes:
        name: Identifier for the code unit (function/class/module name).
        source: The file or snippet from which the contract was extracted.
        declared_intents: Set of intent categories inferred from signals.
        docstring: The raw docstring, if any.
        type_annotations: Type hints that inform intent inference.
        decorators: Decorators applied to the code unit.
        location: Source location of the code unit.
        confidence: 0.0-1.0 confidence score for the extracted intent.
        metadata: Extra key/value pairs for extensibility.
    """

    name: str
    source: str
    declared_intents: set[IntentCategory] = field(default_factory=set)
    docstring: str | None = None
    type_annotations: dict[str, str] = field(default_factory=dict)
    decorators: list[str] = field(default_factory=list)
    location: SourceLocation | None = None
    confidence: float = 1.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dictionary."""
        return {
            "name": self.name,
            "source": self.source,
            "declared_intents": [i.value for i in self.declared_intents],
            "docstring": self.docstring,
            "type_annotations": self.type_annotations,
            "decorators": self.decorators,
            "location": self.location.to_dict() if self.location else None,
            "confidence": self.confidence,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SemanticContract:
        """Deserialize from a plain dictionary."""
        intents = {IntentCategory(v) for v in data.get("declared_intents", [])}
        loc_data = data.get("location")
        location = SourceLocation.from_dict(loc_data) if loc_data else None
        return cls(
            name=data["name"],
            source=data["source"],
            declared_intents=intents,
            docstring=data.get("docstring"),
            type_annotations=data.get("type_annotations", {}),
            decorators=data.get("decorators", []),
            location=location,
            confidence=data.get("confidence", 1.0),
            metadata=data.get("metadata", {}),
        )


@dataclass
class Capability:
    """A discrete capability discovered in code.

    Attributes:
        category: What kind of capability this is.
        description: Human-readable explanation of the capability.
        evidence: The code construct that provides this capability
            (e.g. ``subprocess.run``, ``open(..., 'w')``).
        location: Where in the source this capability was found.
        reachability: How reachable this capability is from the entry point.
        confidence: 0.0-1.0 confidence in the detection.
        metadata: Extra key/value pairs.
    """

    category: CapabilityCategory
    description: str
    evidence: str
    location: SourceLocation | None = None
    reachability: ReachabilityStatus = ReachabilityStatus.REACHABLE
    confidence: float = 1.0
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def intent_category(self) -> IntentCategory:
        """Map this capability to its corresponding intent category."""
        return CAPABILITY_TO_INTENT.get(self.category, IntentCategory.UNKNOWN)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dictionary."""
        return {
            "category": self.category.value,
            "description": self.description,
            "evidence": self.evidence,
            "location": self.location.to_dict() if self.location else None,
            "reachability": self.reachability.value,
            "confidence": self.confidence,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Capability:
        """Deserialize from a plain dictionary."""
        loc_data = data.get("location")
        location = SourceLocation.from_dict(loc_data) if loc_data else None
        return cls(
            category=CapabilityCategory(data["category"]),
            description=data["description"],
            evidence=data["evidence"],
            location=location,
            reachability=ReachabilityStatus(data.get("reachability", "REACHABLE")),
            confidence=data.get("confidence", 1.0),
            metadata=data.get("metadata", {}),
        )


@dataclass
class Deviation:
    """A mismatch between declared intent and reachable capability.

    A deviation is the central finding of MythGuardAI. It represents a
    point where the code can do something it never declared an intent
    to do, which is the defining signal of capability drift.

    Attributes:
        id: Unique identifier for this deviation.
        contract: The semantic contract that was violated.
        capability: The capability that exceeds declared intent.
        severity: How serious the deviation is.
        rule_id: The policy rule that triggered this deviation.
        message: Human-readable explanation.
        reachability: Reachability status of the offending capability.
        location: Source location of the deviation.
        metadata: Extra key/value pairs.
    """

    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    contract: SemanticContract | None = None
    capability: Capability | None = None
    severity: DeviationSeverity = DeviationSeverity.MEDIUM
    rule_id: str = ""
    message: str = ""
    reachability: ReachabilityStatus = ReachabilityStatus.REACHABLE
    location: SourceLocation | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dictionary."""
        return {
            "id": self.id,
            "contract": self.contract.to_dict() if self.contract else None,
            "capability": self.capability.to_dict() if self.capability else None,
            "severity": self.severity.value,
            "rule_id": self.rule_id,
            "message": self.message,
            "reachability": self.reachability.value,
            "location": self.location.to_dict() if self.location else None,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Deviation:
        """Deserialize from a plain dictionary."""
        contract_data = data.get("contract")
        contract = SemanticContract.from_dict(contract_data) if contract_data else None
        cap_data = data.get("capability")
        capability = Capability.from_dict(cap_data) if cap_data else None
        loc_data = data.get("location")
        location = SourceLocation.from_dict(loc_data) if loc_data else None
        return cls(
            id=data.get("id", uuid.uuid4().hex[:12]),
            contract=contract,
            capability=capability,
            severity=DeviationSeverity(data.get("severity", "MEDIUM")),
            rule_id=data.get("rule_id", ""),
            message=data.get("message", ""),
            reachability=ReachabilityStatus(data.get("reachability", "REACHABLE")),
            location=location,
            metadata=data.get("metadata", {}),
        )


@dataclass
class RiskScore:
    """Composite risk score derived from a collection of deviations.

    The score is a weighted sum where higher-severity deviations
    contribute more. It is always recomputed deterministically from
    the deviation list, making it fully auditable.

    Attributes:
        total: 0.0-100.0 composite score.
        critical_count: Number of CRITICAL deviations.
        high_count: Number of HIGH deviations.
        medium_count: Number of MEDIUM deviations.
        low_count: Number of LOW deviations.
    """

    SEVERITY_WEIGHTS: dict[DeviationSeverity, float] = field(
        default_factory=lambda: {
            DeviationSeverity.CRITICAL: 25.0,
            DeviationSeverity.HIGH: 15.0,
            DeviationSeverity.MEDIUM: 7.0,
            DeviationSeverity.LOW: 2.0,
        },
        repr=False,
    )

    total: float = 0.0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0

    @classmethod
    def from_deviations(cls, deviations: list[Deviation]) -> RiskScore:
        """Compute a risk score from a list of deviations.

        The formula is::

            total = min(100, sum(weight * count_for_severity))

        Args:
            deviations: The deviations to score.

        Returns:
            A ``RiskScore`` instance with counts and the composite total.
        """
        counts: dict[DeviationSeverity, int] = {
            DeviationSeverity.CRITICAL: 0,
            DeviationSeverity.HIGH: 0,
            DeviationSeverity.MEDIUM: 0,
            DeviationSeverity.LOW: 0,
        }
        for dev in deviations:
            counts[dev.severity] = counts.get(dev.severity, 0) + 1

        weights = {
            DeviationSeverity.CRITICAL: 25.0,
            DeviationSeverity.HIGH: 15.0,
            DeviationSeverity.MEDIUM: 7.0,
            DeviationSeverity.LOW: 2.0,
        }

        total = sum(weights[sev] * cnt for sev, cnt in counts.items())
        total = min(100.0, total)

        return cls(
            total=round(total, 2),
            critical_count=counts[DeviationSeverity.CRITICAL],
            high_count=counts[DeviationSeverity.HIGH],
            medium_count=counts[DeviationSeverity.MEDIUM],
            low_count=counts[DeviationSeverity.LOW],
        )

    @property
    def grade(self) -> str:
        """Letter grade based on the total score.

        A (0-20): Minimal risk.
        B (21-40): Low risk.
        C (41-60): Moderate risk.
        D (61-80): High risk.
        F (81-100): Critical risk.
        """
        if self.total <= 20:
            return "A"
        if self.total <= 40:
            return "B"
        if self.total <= 60:
            return "C"
        if self.total <= 80:
            return "D"
        return "F"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dictionary."""
        return {
            "total": self.total,
            "grade": self.grade,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
        }


@dataclass
class ScanResult:
    """Complete result of a MythGuardAI scan.

    Aggregates all deviations, the risk score, and metadata about the
    scan itself. Fully serializable and deterministic: the same input
    always produces the same output.

    Attributes:
        scan_id: Unique identifier for this scan run.
        target: The path or code string that was scanned.
        timestamp: When the scan was performed (UTC).
        deviations: All deviations found during the scan.
        contracts: All semantic contracts extracted.
        capabilities: All capabilities discovered.
        risk_score: Composite risk score computed from deviations.
        duration_ms: Wall-clock duration of the scan in milliseconds.
        metadata: Extra key/value pairs (e.g. scanner version, options).
    """

    scan_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    target: str = ""
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    deviations: list[Deviation] = field(default_factory=list)
    contracts: list[SemanticContract] = field(default_factory=list)
    capabilities: list[Capability] = field(default_factory=list)
    risk_score: RiskScore = field(default_factory=RiskScore)
    duration_ms: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def compute_risk_score(self) -> RiskScore:
        """Recompute the risk score from current deviations."""
        self.risk_score = RiskScore.from_deviations(self.deviations)
        return self.risk_score

    @property
    def has_deviations(self) -> bool:
        """Whether any deviations were found."""
        return len(self.deviations) > 0

    @property
    def has_critical(self) -> bool:
        """Whether any CRITICAL deviations exist."""
        return any(d.severity == DeviationSeverity.CRITICAL for d in self.deviations)

    def filter_by_severity(
        self, threshold: DeviationSeverity
    ) -> list[Deviation]:
        """Return deviations at or above the given severity threshold."""
        return [d for d in self.deviations if d.severity >= threshold]

    def fingerprint(self) -> str:
        """Deterministic SHA-256 fingerprint of this scan result.

        Useful for comparing two scans for identical findings without
        relying on scan_id or timestamp.
        """
        parts: list[str] = []
        for dev in sorted(self.deviations, key=lambda d: d.id):
            parts.append(
                f"{dev.rule_id}:{dev.severity.value}:"
                f"{dev.capability.category.value if dev.capability else ''}:"
                f"{dev.reachability.value}"
            )
        content = "|".join(parts)
        return hashlib.sha256(content.encode()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dictionary."""
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "timestamp": self.timestamp,
            "deviations": [d.to_dict() for d in self.deviations],
            "contracts": [c.to_dict() for c in self.contracts],
            "capabilities": [c.to_dict() for c in self.capabilities],
            "risk_score": self.risk_score.to_dict(),
            "duration_ms": self.duration_ms,
            "metadata": self.metadata,
            "fingerprint": self.fingerprint(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScanResult:
        """Deserialize from a plain dictionary."""
        deviations = [Deviation.from_dict(d) for d in data.get("deviations", [])]
        contracts = [SemanticContract.from_dict(c) for c in data.get("contracts", [])]
        capabilities = [Capability.from_dict(c) for c in data.get("capabilities", [])]
        risk_data = data.get("risk_score", {})
        risk_score = RiskScore(
            total=risk_data.get("total", 0.0),
            critical_count=risk_data.get("critical_count", 0),
            high_count=risk_data.get("high_count", 0),
            medium_count=risk_data.get("medium_count", 0),
            low_count=risk_data.get("low_count", 0),
        )
        return cls(
            scan_id=data.get("scan_id", uuid.uuid4().hex),
            target=data.get("target", ""),
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            deviations=deviations,
            contracts=contracts,
            capabilities=capabilities,
            risk_score=risk_score,
            duration_ms=data.get("duration_ms", 0.0),
            metadata=data.get("metadata", {}),
        )
