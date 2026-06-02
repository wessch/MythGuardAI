"""Core scanner for MythGuardAI.

``MythGuardScanner`` is the main entry point for scanning code. It
orchestrates contract extraction, capability mapping, reachability
analysis, and deviation detection according to the triad:

    Intent -> Capability -> Reachability

A security failure occurs when reachable capability diverges from
declared intent.
"""

from __future__ import annotations

import ast
import time
from pathlib import Path
from typing import Any

from mythguardai.analyzers.python_analyzer import PythonAnalyzer
from mythguardai.config import ScanConfig, default_config
from mythguardai.engine.contract import ContractExtractor
from mythguardai.exceptions import ScanError
from mythguardai.models import (
    Capability,
    CapabilityCategory,
    Deviation,
    DeviationSeverity,
    IntentCategory,
    ReachabilityStatus,
    RiskScore,
    ScanResult,
    SemanticContract,
    SourceLocation,
)
from mythguardai.policies.policy_engine import PolicyEngine

# Attempt to import the JavaScript analyzer
try:
    from mythguardai.analyzers.javascript_analyzer import JavaScriptAnalyzer
except ImportError:  # pragma: no cover
    JavaScriptAnalyzer = None  # type: ignore[assignment,misc]


class MythGuardScanner:
    """Main scanner that detects capability drift in code.

    The scanner compares declared intent (semantic contracts) against
    reachable capability to find semantic deviations. All operations
    are deterministic, offline-capable, and fully auditable.

    Usage::

        scanner = MythGuardScanner()
        result = scanner.scan_path("./src")
        print(result.risk_score.total)
    """

    def __init__(self, config: ScanConfig | None = None) -> None:
        """Initialize the scanner with optional configuration.

        Args:
            config: Scan configuration. Uses defaults if not provided.
        """
        self.config = config or default_config()
        self._contract_extractor = ContractExtractor()
        self._policy_engine = PolicyEngine()
        self._python_analyzer = PythonAnalyzer()
        self._js_analyzer = JavaScriptAnalyzer() if JavaScriptAnalyzer else None

        # Load custom policies from configured directories
        for policy_dir in self.config.policy_dirs:
            self._policy_engine.load_custom_policies(policy_dir)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_path(self, path: str | Path) -> ScanResult:
        """Scan all supported files under a directory path.

        Recursively walks the directory, skipping ignored directories
        and files according to the scan configuration.

        Args:
            path: Root directory to scan.

        Returns:
            A ``ScanResult`` with aggregated findings.

        Raises:
            ScanError: If the path does not exist or is not accessible.
        """
        start_time = time.monotonic()
        root = Path(path)

        if not root.exists():
            raise ScanError(f"Path does not exist: {root}", path=str(root))
        if not root.is_dir():
            raise ScanError(f"Path is not a directory: {root}", path=str(root))

        all_deviations: list[Deviation] = []
        all_contracts: list[SemanticContract] = []
        all_capabilities: list[Capability] = []

        for file_path in self._walk_files(root):
            try:
                result = self.scan_file(file_path)
            except ScanError:
                # Skip files that cannot be scanned, but continue
                continue

            all_deviations.extend(result.deviations)
            all_contracts.extend(result.contracts)
            all_capabilities.extend(result.capabilities)

        duration_ms = (time.monotonic() - start_time) * 1000

        scan_result = ScanResult(
            target=str(root),
            deviations=all_deviations,
            contracts=all_contracts,
            capabilities=all_capabilities,
            duration_ms=round(duration_ms, 2),
            metadata={"scanner_version": "0.1.0", "config": self.config.to_dict()},
        )
        scan_result.compute_risk_score()
        return scan_result

    def scan_file(self, file_path: str | Path) -> ScanResult:
        """Scan a single file.

        Detects the language from the file extension and delegates to
        the appropriate analyzer.

        Args:
            file_path: Path to the file to scan.

        Returns:
            A ``ScanResult`` with findings from the file.

        Raises:
            ScanError: If the file cannot be read or parsed.
        """
        start_time = time.monotonic()
        fpath = Path(file_path)

        if not fpath.exists():
            raise ScanError(f"File does not exist: {fpath}", path=str(fpath))
        if not fpath.is_file():
            raise ScanError(f"Path is not a file: {fpath}", path=str(fpath))

        language = self.config.detect_language(str(fpath))
        if language is None:
            raise ScanError(
                f"Unsupported file type: {fpath.suffix}",
                path=str(fpath),
            )

        try:
            code = fpath.read_text(encoding="utf-8")
        except OSError as exc:
            raise ScanError(
                f"Cannot read file: {exc}",
                path=str(fpath),
            ) from exc

        result = self.scan_code(code, language, source_file=str(fpath))
        result.target = str(fpath)
        result.duration_ms = round((time.monotonic() - start_time) * 1000, 2)
        return result

    def scan_code(
        self,
        code_string: str,
        language: str,
        *,
        source_file: str = "<string>",
    ) -> ScanResult:
        """Scan a code string directly.

        Args:
            code_string: The source code to analyze.
            language: Language identifier (``"python"`` or ``"javascript"``).
            source_file: Logical file name for source locations.

        Returns:
            A ``ScanResult`` with findings.

        Raises:
            ScanError: If the code cannot be parsed.
        """
        start_time = time.monotonic()

        # Step 1: Extract intent (semantic contracts)
        contracts = self._extract_intent(code_string, language, source_file)

        # Step 2: Map capabilities
        capabilities = self._map_capabilities(code_string, language, source_file)

        # Step 3: Detect deviations
        deviations = self._detect_deviations(contracts, capabilities)

        # Step 4: Compute reachability
        deviations = self._compute_reachability(deviations, code_string, language)

        # Filter by severity threshold
        deviations = [
            d for d in deviations
            if d.severity >= self.config.severity_threshold
        ]

        # Filter unreachable if configured
        if not self.config.include_unreachable:
            deviations = [
                d for d in deviations
                if d.reachability != ReachabilityStatus.UNREACHABLE
            ]

        duration_ms = (time.monotonic() - start_time) * 1000

        scan_result = ScanResult(
            target=source_file,
            deviations=deviations,
            contracts=contracts,
            capabilities=capabilities,
            duration_ms=round(duration_ms, 2),
            metadata={
                "scanner_version": "0.1.0",
                "language": language,
            },
        )
        scan_result.compute_risk_score()
        return scan_result

    # ------------------------------------------------------------------
    # Internal pipeline stages
    # ------------------------------------------------------------------

    def _extract_intent(
        self,
        code_string: str,
        language: str,
        source_file: str,
    ) -> list[SemanticContract]:
        """Stage 1: Extract semantic contracts (declared intent).

        Parses the source code and extracts contracts from all named
        code units: functions, classes, and the module itself.
        """
        contracts: list[SemanticContract] = []

        if language == "python":
            try:
                tree = ast.parse(code_string, filename=source_file)
            except SyntaxError as exc:
                raise ScanError(
                    f"Python syntax error: {exc}",
                    path=source_file,
                ) from exc

            self._contract_extractor.set_source_file(source_file)

            # Module-level contract
            module_contract = self._contract_extractor.extract_from_module(tree)
            contracts.append(module_contract)

            # Function and class contracts
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    contracts.append(
                        self._contract_extractor.extract_from_function(node)
                    )
                elif isinstance(node, ast.ClassDef):
                    contracts.append(
                        self._contract_extractor.extract_from_class(node)
                    )

        elif language == "javascript":
            # For JavaScript, we build a simplified contract from
            # function and variable names using regex patterns
            contracts = self._extract_js_contracts(code_string, source_file)

        return contracts

    def _map_capabilities(
        self,
        code_string: str,
        language: str,
        source_file: str,
    ) -> list[Capability]:
        """Stage 2: Map all capabilities in the code.

        Uses language-specific analyzers to discover what the code
        can actually do.
        """
        if language == "python":
            try:
                tree = ast.parse(code_string, filename=source_file)
            except SyntaxError as exc:
                raise ScanError(
                    f"Python syntax error: {exc}",
                    path=source_file,
                ) from exc
            return self._python_analyzer.analyze(tree, source_file=source_file)

        elif language == "javascript":
            if self._js_analyzer:
                return self._js_analyzer.analyze(code_string, source_file=source_file)
            return []

        return []

    def _detect_deviations(
        self,
        contracts: list[SemanticContract],
        capabilities: list[Capability],
    ) -> list[Deviation]:
        """Stage 3: Detect deviations between intent and capability.

        Evaluates each contract against discovered capabilities using
        the policy engine.
        """
        deviations: list[Deviation] = []

        for contract in contracts:
            # Find capabilities in the same code unit
            unit_caps = self._capabilities_for_contract(contract, capabilities)
            if not unit_caps:
                continue

            new_devs = self._policy_engine.evaluate(contract, unit_caps)
            deviations.extend(new_devs)

        # Also check module-level: capabilities not covered by any contract
        module_caps = self._find_orphan_capabilities(contracts, capabilities)
        for cap in module_caps:
            deviations.append(
                Deviation(
                    contract=None,
                    capability=cap,
                    severity=DeviationSeverity.MEDIUM,
                    rule_id="MG-ORPHAN-001",
                    message=(
                        f"Capability {cap.category.value} at "
                        f"{cap.location.file}:{cap.location.line} "
                        f"is not covered by any semantic contract"
                    ),
                    reachability=cap.reachability,
                    location=cap.location,
                )
            )

        return deviations

    def _compute_reachability(
        self,
        deviations: list[Deviation],
        code_string: str,
        language: str,
    ) -> list[Deviation]:
        """Stage 4: Compute reachability for each deviation.

        Determines whether the capability underlying each deviation is
        actually reachable from the entry point of the code unit.
        """
        if language != "python":
            # For non-Python languages, assume REACHABLE
            return deviations

        try:
            tree = ast.parse(code_string)
        except SyntaxError:
            return deviations

        # Collect all function and class definitions
        function_defs: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                function_defs.add(node.name)

        # Simple reachability heuristic: if a function is defined at
        # module level (not nested), it is REACHABLE. If it is only
        # called inside conditional blocks, it is CONDITIONAL.
        for dev in deviations:
            if dev.capability and dev.capability.location:
                loc = dev.capability.location
                # Check if the capability is inside a function
                cap_func = self._find_enclosing_function(tree, loc.line)
                if cap_func is None:
                    # Module-level: REACHABLE
                    dev.reachability = ReachabilityStatus.REACHABLE
                else:
                    # Inside a function: check if the function itself
                    # is module-level (REACHABLE) or nested (CONDITIONAL)
                    if cap_func in function_defs:
                        dev.reachability = ReachabilityStatus.REACHABLE
                    else:
                        dev.reachability = ReachabilityStatus.CONDITIONAL
            else:
                dev.reachability = ReachabilityStatus.REACHABLE

        return deviations

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _walk_files(self, root: Path) -> list[Path]:
        """Walk a directory tree and return scannable file paths."""
        files: list[Path] = []
        for item in root.rglob("*"):
            if self.config.should_ignore(item):
                continue
            if item.is_file():
                language = self.config.detect_language(str(item))
                if language is not None:
                    files.append(item)
        return sorted(files)

    def _capabilities_for_contract(
        self,
        contract: SemanticContract,
        capabilities: list[Capability],
    ) -> list[Capability]:
        """Find capabilities that belong to the same code unit as a contract."""
        if contract.location is None:
            return []

        contract_start = contract.location.line
        contract_end = contract.location.end_line or contract_start

        matching: list[Capability] = []
        for cap in capabilities:
            if cap.location is None:
                continue
            if cap.location.file != contract.location.file:
                continue
            if contract_start <= cap.location.line <= contract_end:
                matching.append(cap)

        return matching

    def _find_orphan_capabilities(
        self,
        contracts: list[SemanticContract],
        capabilities: list[Capability],
    ) -> list[Capability]:
        """Find capabilities not covered by any contract's source range."""
        covered_lines: dict[str, set[int]] = {}

        for contract in contracts:
            if contract.location is None:
                continue
            file = contract.location.file
            if file not in covered_lines:
                covered_lines[file] = set()
            start = contract.location.line
            end = contract.location.end_line or start
            for line in range(start, end + 1):
                covered_lines[file].add(line)

        orphans: list[Capability] = []
        for cap in capabilities:
            if cap.location is None:
                orphans.append(cap)
                continue
            file = cap.location.file
            line = cap.location.line
            if file not in covered_lines or line not in covered_lines[file]:
                orphans.append(cap)

        return orphans

    def _find_enclosing_function(self, tree: ast.Module, line: int) -> str | None:
        """Find the name of the function enclosing a given line number."""
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                start = node.lineno
                end = getattr(node, "end_lineno", None) or start
                if start <= line <= end:
                    return node.name
        return None

    def _extract_js_contracts(
        self,
        code_string: str,
        source_file: str,
    ) -> list[SemanticContract]:
        """Extract simplified contracts from JavaScript code.

        Uses regex patterns to identify function declarations and
        infer intent from their names.
        """
        import re

        contracts: list[SemanticContract] = []

        # Module-level contract
        module_contract = SemanticContract(
            name=source_file,
            source=source_file,
            declared_intents={IntentCategory.COMPUTATION},
            location=SourceLocation(file=source_file),
            confidence=0.5,
        )
        contracts.append(module_contract)

        # Match function declarations: function name, const name =, let name =, var name =
        func_pattern = re.compile(
            r"(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:function|\())",
            re.MULTILINE,
        )

        for match in func_pattern.finditer(code_string):
            name = match.group(1) or match.group(2)
            if not name:
                continue

            intents = self._contract_extractor._infer_intents_from_name(name)
            if not intents:
                intents = {IntentCategory.COMPUTATION}

            # Approximate line number
            line = code_string[: match.start()].count("\n") + 1

            contracts.append(
                SemanticContract(
                    name=name,
                    source=source_file,
                    declared_intents=intents,
                    location=SourceLocation(file=source_file, line=line),
                    confidence=0.6,
                )
            )

        return contracts
