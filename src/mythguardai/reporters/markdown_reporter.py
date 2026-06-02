"""Markdown reporter for MythGuardAI.

Produces a human-readable Markdown report from a ``ScanResult``,
suitable for documentation, code review comments, or CI artifacts.
"""

from __future__ import annotations

from typing import Any

from mythguardai.models import (
    Deviation,
    DeviationSeverity,
    ReachabilityStatus,
    RiskScore,
    ScanResult,
)

# Severity emoji indicators
_SEVERITY_ICONS: dict[DeviationSeverity, str] = {
    DeviationSeverity.CRITICAL: ":red_circle:",
    DeviationSeverity.HIGH: ":large_orange_diamond:",
    DeviationSeverity.MEDIUM: ":large_yellow_circle:",
    DeviationSeverity.LOW: ":large_blue_circle:",
}

_SEVERITY_TEXT: dict[DeviationSeverity, str] = {
    DeviationSeverity.CRITICAL: "CRITICAL",
    DeviationSeverity.HIGH: "HIGH",
    DeviationSeverity.MEDIUM: "MEDIUM",
    DeviationSeverity.LOW: "LOW",
}


class MarkdownReporter:
    """Formats scan results as Markdown.

    Produces a structured Markdown document with an executive summary,
    risk score, and detailed deviation table.

    Usage::

        reporter = MarkdownReporter()
        output = reporter.render(scan_result)
        print(output)
    """

    def render(self, result: ScanResult) -> str:
        """Render a scan result as a Markdown string.

        Args:
            result: The scan result to render.

        Returns:
            A formatted Markdown string.
        """
        sections: list[str] = []

        # Header
        sections.append("# MythGuardAI Security Report")
        sections.append("")

        # Executive summary
        sections.append("## Executive Summary")
        sections.append("")
        sections.append(f"- **Target**: `{result.target}`")
        sections.append(f"- **Scan ID**: `{result.scan_id}`")
        sections.append(f"- **Timestamp**: {result.timestamp}")
        sections.append(f"- **Duration**: {result.duration_ms:.1f} ms")
        sections.append(
            f"- **Deviations Found**: {len(result.deviations)}"
        )
        sections.append(
            f"- **Risk Score**: {result.risk_score.total}/100 (Grade: {result.risk_score.grade})"
        )
        sections.append("")

        # Risk breakdown
        score = result.risk_score
        sections.append("### Risk Breakdown")
        sections.append("")
        sections.append("| Severity | Count |")
        sections.append("|----------|-------|")
        sections.append(f"| CRITICAL | {score.critical_count} |")
        sections.append(f"| HIGH | {score.high_count} |")
        sections.append(f"| MEDIUM | {score.medium_count} |")
        sections.append(f"| LOW | {score.low_count} |")
        sections.append("")

        # Fingerprint
        sections.append(f"Fingerprint: `{result.fingerprint()}`")
        sections.append("")

        # Deviations
        if result.deviations:
            sections.append("## Deviations")
            sections.append("")

            # Group by severity
            for severity in [
                DeviationSeverity.CRITICAL,
                DeviationSeverity.HIGH,
                DeviationSeverity.MEDIUM,
                DeviationSeverity.LOW,
            ]:
                devs = [
                    d for d in result.deviations if d.severity == severity
                ]
                if not devs:
                    continue

                icon = _SEVERITY_ICONS[severity]
                label = _SEVERITY_TEXT[severity]
                sections.append(f"### {icon} {label} ({len(devs)})")
                sections.append("")

                for dev in devs:
                    sections.append(self._render_deviation(dev))

        else:
            sections.append("## No Deviations Found")
            sections.append("")
            sections.append(
                "No capability drift was detected. All reachable "
                "capabilities align with declared intent."
            )
            sections.append("")

        # Contracts
        if result.contracts:
            sections.append("## Semantic Contracts")
            sections.append("")
            sections.append("| Name | Declared Intents | Confidence |")
            sections.append("|------|-----------------|------------|")
            for contract in result.contracts:
                intents = ", ".join(
                    sorted(i.value for i in contract.declared_intents)
                )
                sections.append(
                    f"| `{contract.name}` | {intents} | "
                    f"{contract.confidence:.0%} |"
                )
            sections.append("")

        # Capabilities
        if result.capabilities:
            sections.append("## Discovered Capabilities")
            sections.append("")
            sections.append("| Category | Evidence | Location | Reachability |")
            sections.append("|----------|----------|----------|--------------|")
            for cap in result.capabilities:
                loc = (
                    f"{cap.location.file}:{cap.location.line}"
                    if cap.location
                    else "N/A"
                )
                sections.append(
                    f"| {cap.category.value} | `{cap.evidence}` | "
                    f"{loc} | {cap.reachability.value} |"
                )
            sections.append("")

        return "\n".join(sections)

    def _render_deviation(self, dev: Deviation) -> str:
        """Render a single deviation as Markdown."""
        lines: list[str] = []

        rule_id = dev.rule_id or "N/A"
        contract_name = dev.contract.name if dev.contract else "N/A"
        cap_evidence = dev.capability.evidence if dev.capability else "N/A"
        location = (
            f"{dev.location.file}:{dev.location.line}"
            if dev.location
            else "N/A"
        )

        lines.append(f"**[{rule_id}]** {dev.message}")
        lines.append("")
        lines.append(f"- Contract: `{contract_name}`")
        lines.append(f"- Capability: `{cap_evidence}`")
        lines.append(f"- Location: {location}")
        lines.append(f"- Reachability: {dev.reachability.value}")
        lines.append("")

        return "\n".join(lines)

    def render_to_file(self, result: ScanResult, path: str) -> None:
        """Write a scan result to a Markdown file.

        Args:
            result: The scan result to render.
            path: Output file path.
        """
        content = self.render(result)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
