"""SARIF reporter for MythGuardAI.

Produces SARIF (Static Analysis Results Interchange Format) output
for integration with GitHub Code Scanning, Azure DevOps, and other
tools that consume SARIF.

SARIF spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

import json
from typing import Any

from mythguardai.models import (
    Deviation,
    DeviationSeverity,
    ReachabilityStatus,
    ScanResult,
)

# SARIF severity level mapping
_SEVERITY_TO_SARIF_LEVEL: dict[DeviationSeverity, str] = {
    DeviationSeverity.CRITICAL: "error",
    DeviationSeverity.HIGH: "error",
    DeviationSeverity.MEDIUM: "warning",
    DeviationSeverity.LOW: "note",
}

# SARIF rank mapping (0.0 to 100.0, higher = more severe)
_SEVERITY_TO_SARIF_RANK: dict[DeviationSeverity, float] = {
    DeviationSeverity.CRITICAL: 90.0,
    DeviationSeverity.HIGH: 70.0,
    DeviationSeverity.MEDIUM: 50.0,
    DeviationSeverity.LOW: 20.0,
}


class SarifReporter:
    """Formats scan results as SARIF.

    Produces a SARIF v2.1.0 document suitable for uploading to
    GitHub Code Scanning or any SARIF-compatible tool.

    Usage::

        reporter = SarifReporter()
        output = reporter.render(scan_result)
        # Upload to GitHub:
        # gh api /repos/:owner/:repo/code-scanning/sarifs ...
    """

    SARIF_VERSION = "2.1.0"
    SCHEMA_URI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

    def render(self, result: ScanResult, *, indent: int = 2) -> str:
        """Render a scan result as a SARIF JSON string.

        Args:
            result: The scan result to render.
            indent: JSON indentation level.

        Returns:
            A SARIF-formatted JSON string.
        """
        sarif = self._build_sarif(result)
        return json.dumps(sarif, indent=indent, sort_keys=False)

    def render_to_file(
        self, result: ScanResult, path: str, *, indent: int = 2
    ) -> None:
        """Write a scan result to a SARIF file.

        Args:
            result: The scan result to render.
            path: Output file path.
            indent: JSON indentation level.
        """
        content = self.render(result, indent=indent)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)

    def _build_sarif(self, result: ScanResult) -> dict[str, Any]:
        """Build the SARIF document structure."""
        # Collect unique rule IDs from deviations
        rules: dict[str, dict[str, Any]] = {}
        for dev in result.deviations:
            if dev.rule_id and dev.rule_id not in rules:
                rules[dev.rule_id] = {
                    "id": dev.rule_id,
                    "name": dev.rule_id,
                    "shortDescription": {
                        "text": self._rule_short_description(dev.rule_id)
                    },
                    "fullDescription": {
                        "text": self._rule_full_description(dev.rule_id)
                    },
                    "helpUri": f"https://github.com/wessch/MythGuardAI/blob/main/docs/rules/{dev.rule_id}.md",
                    "defaultConfiguration": {
                        "level": self._default_level_for_rule(dev.rule_id),
                    },
                    "properties": {
                        "tags": ["security", "semantic-drift"],
                    },
                }

        # Build results array
        results: list[dict[str, Any]] = []
        for dev in result.deviations:
            results.append(self._build_result(dev))

        sarif: dict[str, Any] = {
            "$schema": self.SCHEMA_URI,
            "version": self.SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "MythGuardAI",
                            "version": "0.1.0",
                            "semanticVersion": "0.1.0",
                            "informationUri": "https://github.com/wessch/MythGuardAI",
                            "rules": list(rules.values()),
                        }
                    },
                    "results": results,
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "startTimeUtc": result.timestamp,
                        }
                    ],
                    "properties": {
                        "scanId": result.scan_id,
                        "target": result.target,
                        "riskScore": result.risk_score.to_dict(),
                        "fingerprint": result.fingerprint(),
                        "durationMs": result.duration_ms,
                    },
                }
            ],
        }

        return sarif

    def _build_result(self, dev: Deviation) -> dict[str, Any]:
        """Build a single SARIF result object from a deviation."""
        result: dict[str, Any] = {
            "ruleId": dev.rule_id,
            "level": _SEVERITY_TO_SARIF_LEVEL.get(dev.severity, "warning"),
            "rank": _SEVERITY_TO_SARIF_RANK.get(dev.severity, 50.0),
            "message": {
                "text": dev.message,
            },
        }

        # Add location if available
        if dev.location or (dev.capability and dev.capability.location):
            loc = dev.location or (dev.capability.location if dev.capability else None)
            if loc:
                result["locations"] = [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": loc.file,
                            },
                            "region": {
                                "startLine": max(loc.line, 1),
                                "startColumn": max(loc.col + 1, 1),
                            },
                        }
                    }
                ]

        # Add related locations for the capability
        if (
            dev.capability
            and dev.capability.location
            and dev.location
            and dev.capability.location.file != dev.location.file
        ):
            result["relatedLocations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": dev.capability.location.file,
                        },
                        "region": {
                            "startLine": max(dev.capability.location.line, 1),
                        },
                    }
                }
            ]

        # Add properties
        result["properties"] = {
            "deviationId": dev.id,
            "severity": dev.severity.value,
            "reachability": dev.reachability.value,
            "contractName": dev.contract.name if dev.contract else None,
            "capabilityCategory": (
                dev.capability.category.value if dev.capability else None
            ),
        }

        return result

    def _rule_short_description(self, rule_id: str) -> str:
        """Get a short description for a rule ID."""
        descriptions: dict[str, str] = {
            "MG-SUB-001": "Subprocess execution in non-execution context",
            "MG-FW-001": "File write in read-only context",
            "MG-NET-001": "Network access in non-network context",
            "MG-PRIV-001": "Privilege escalation in non-privileged context",
            "MG-EXP-001": "Capability exceeds declared intent",
            "MG-ORPHAN-001": "Capability not covered by any semantic contract",
        }
        return descriptions.get(rule_id, f"MythGuardAI policy: {rule_id}")

    def _rule_full_description(self, rule_id: str) -> str:
        """Get a full description for a rule ID."""
        descriptions: dict[str, str] = {
            "MG-SUB-001": (
                "A code unit that does not declare subprocess or dynamic execution "
                "intent was found to contain subprocess capability. This indicates "
                "capability drift: the code can execute external processes without "
                "declaring that intent."
            ),
            "MG-FW-001": (
                "A code unit that declares only file-read intent was found to "
                "contain file-write capability. This indicates capability drift: "
                "the code can modify files without declaring that intent."
            ),
            "MG-NET-001": (
                "A code unit that does not declare network intent was found to "
                "contain network capability. This indicates capability drift: "
                "the code can communicate over the network without declaring "
                "that intent, posing exfiltration or C2 risk."
            ),
            "MG-PRIV-001": (
                "A code unit that does not declare privilege intent was found to "
                "contain privilege-escalation capability. This is a critical "
                "capability drift signal: the code can escalate privileges "
                "without declaring that intent."
            ),
            "MG-EXP-001": (
                "A code unit contains a capability whose intent category is not "
                "present in its semantic contract. This is the broadest form of "
                "capability drift: any reachable capability that exceeds declared "
                "intent represents a potential security concern."
            ),
            "MG-ORPHAN-001": (
                "A capability was found that is not covered by any semantic "
                "contract in the same code unit. This may indicate dead code, "
                "missing documentation, or intentionally hidden functionality."
            ),
        }
        return descriptions.get(rule_id, f"MythGuardAI detected a policy violation for rule {rule_id}.")

    def _default_level_for_rule(self, rule_id: str) -> str:
        """Get the default SARIF level for a rule ID."""
        level_map: dict[str, str] = {
            "MG-SUB-001": "error",
            "MG-FW-001": "warning",
            "MG-NET-001": "error",
            "MG-PRIV-001": "error",
            "MG-EXP-001": "warning",
            "MG-ORPHAN-001": "note",
        }
        return level_map.get(rule_id, "warning")
