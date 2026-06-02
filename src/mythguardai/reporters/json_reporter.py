"""JSON reporter for MythGuardAI.

Produces a structured JSON representation of a ``ScanResult`` suitable
for programmatic consumption, piping to ``jq``, or archival.
"""

from __future__ import annotations

import json
from typing import Any

from mythguardai.models import ScanResult


class JsonReporter:
    """Formats scan results as JSON.

    The output is deterministic: the same ``ScanResult`` always
    produces the same JSON (modulo the scan timestamp).

    Usage::

        reporter = JsonReporter()
        output = reporter.render(scan_result)
        print(output)
    """

    def render(self, result: ScanResult, *, indent: int = 2) -> str:
        """Render a scan result as a JSON string.

        Args:
            result: The scan result to render.
            indent: JSON indentation level.

        Returns:
            A formatted JSON string.
        """
        return json.dumps(result.to_dict(), indent=indent, sort_keys=False)

    def render_to_file(self, result: ScanResult, path: str, *, indent: int = 2) -> None:
        """Write a scan result to a JSON file.

        Args:
            result: The scan result to render.
            path: Output file path.
            indent: JSON indentation level.
        """
        content = self.render(result, indent=indent)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
