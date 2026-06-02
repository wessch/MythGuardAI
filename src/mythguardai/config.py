"""Configuration management for MythGuardAI.

Provides ``ScanConfig`` for controlling scan behavior and
``load_config`` for reading settings from YAML or JSON files.
All defaults are explicit so that scans are fully reproducible
without any configuration file present.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mythguardai.exceptions import ConfigurationError
from mythguardai.models import DeviationSeverity

# Try to import yaml; if unavailable, we still support JSON configs.
try:
    import yaml

    _YAML_AVAILABLE = True
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore[assignment]
    _YAML_AVAILABLE = False


# ---------------------------------------------------------------------------
# Default file extensions recognized by language
# ---------------------------------------------------------------------------

DEFAULT_LANGUAGE_MAP: dict[str, str] = {
    ".py": "python",
    ".pyw": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "javascript",
    ".tsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
}

DEFAULT_IGNORED_DIRS: set[str] = {
    "__pycache__",
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".venv",
    "venv",
    ".env",
    "dist",
    "build",
    ".eggs",
}

DEFAULT_IGNORED_FILES: set[str] = {
    "*.pyc",
    "*.pyo",
    "*.so",
    "*.dll",
    "*.dylib",
    "*.egg",
    "*.whl",
}


@dataclass
class ScanConfig:
    """Configuration for a MythGuardAI scan.

    Attributes:
        severity_threshold: Minimum severity to report.
        languages: Languages to analyze. Empty means all supported.
        policy_dirs: Directories containing custom policy modules.
        output_format: Default output format (json, markdown, sarif).
        output_path: File to write results to. None means stdout.
        ignored_dirs: Directory names to skip during path scans.
        ignored_files: File glob patterns to skip.
        language_map: Mapping from file extension to language name.
        max_file_size_mb: Skip files larger than this (in MiB).
        include_unreachable: Whether to include UNREACHABLE capabilities.
        fail_on_critical: Exit with non-zero code on CRITICAL findings.
        custom_policy_paths: Paths to individual custom policy files.
    """

    severity_threshold: DeviationSeverity = DeviationSeverity.LOW
    languages: set[str] = field(default_factory=set)
    policy_dirs: list[str] = field(default_factory=list)
    output_format: str = "json"
    output_path: str | None = None
    ignored_dirs: set[str] = field(default_factory=lambda: set(DEFAULT_IGNORED_DIRS))
    ignored_files: set[str] = field(default_factory=lambda: set(DEFAULT_IGNORED_FILES))
    language_map: dict[str, str] = field(
        default_factory=lambda: dict(DEFAULT_LANGUAGE_MAP)
    )
    max_file_size_mb: float = 10.0
    include_unreachable: bool = False
    fail_on_critical: bool = True
    custom_policy_paths: list[str] = field(default_factory=list)

    def detect_language(self, file_path: str) -> str | None:
        """Detect the language of a file based on its extension.

        Args:
            file_path: Path to the file.

        Returns:
            Language name or None if the extension is unrecognized.
        """
        suffix = Path(file_path).suffix.lower()
        return self.language_map.get(suffix)

    def should_ignore(self, path: Path) -> bool:
        """Check whether a path should be skipped during scanning.

        Args:
            path: The file or directory path to check.

        Returns:
            True if the path should be ignored.
        """
        # Check directory names
        if path.is_dir() and path.name in self.ignored_dirs:
            return True

        # Check file patterns
        if path.is_file():
            if path.name in self.ignored_dirs:
                return True
            for pattern in self.ignored_files:
                if path.match(pattern):
                    return True
            # Check file size
            try:
                size_mb = path.stat().st_size / (1024 * 1024)
                if size_mb > self.max_file_size_mb:
                    return True
            except OSError:
                return True

        return False

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dictionary."""
        return {
            "severity_threshold": self.severity_threshold.value,
            "languages": sorted(self.languages),
            "policy_dirs": self.policy_dirs,
            "output_format": self.output_format,
            "output_path": self.output_path,
            "ignored_dirs": sorted(self.ignored_dirs),
            "ignored_files": sorted(self.ignored_files),
            "language_map": self.language_map,
            "max_file_size_mb": self.max_file_size_mb,
            "include_unreachable": self.include_unreachable,
            "fail_on_critical": self.fail_on_critical,
            "custom_policy_paths": self.custom_policy_paths,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScanConfig:
        """Create a ScanConfig from a dictionary.

        Args:
            data: Dictionary with configuration values.

        Returns:
            A ScanConfig instance.

        Raises:
            ConfigurationError: If the severity threshold is invalid.
        """
        threshold_str = data.get("severity_threshold", "LOW")
        try:
            threshold = DeviationSeverity(threshold_str)
        except ValueError:
            raise ConfigurationError(
                f"Invalid severity threshold: {threshold_str}",
                details={"severity_threshold": threshold_str},
            )

        languages = set(data.get("languages", []))
        ignored_dirs = set(data.get("ignored_dirs", DEFAULT_IGNORED_DIRS))
        ignored_files = set(data.get("ignored_files", DEFAULT_IGNORED_FILES))
        language_map = data.get("language_map", dict(DEFAULT_LANGUAGE_MAP))

        return cls(
            severity_threshold=threshold,
            languages=languages,
            policy_dirs=data.get("policy_dirs", []),
            output_format=data.get("output_format", "json"),
            output_path=data.get("output_path"),
            ignored_dirs=ignored_dirs,
            ignored_files=ignored_files,
            language_map=language_map,
            max_file_size_mb=data.get("max_file_size_mb", 10.0),
            include_unreachable=data.get("include_unreachable", False),
            fail_on_critical=data.get("fail_on_critical", True),
            custom_policy_paths=data.get("custom_policy_paths", []),
        )


def load_config(path: str | Path) -> ScanConfig:
    """Load a ScanConfig from a YAML or JSON file.

    Args:
        path: Path to the configuration file.

    Returns:
        A ScanConfig populated from the file, with defaults for
        any missing fields.

    Raises:
        ConfigurationError: If the file cannot be read or parsed.
    """
    config_path = Path(path)

    if not config_path.exists():
        raise ConfigurationError(
            f"Configuration file not found: {config_path}",
            config_path=str(config_path),
        )

    try:
        raw = config_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigurationError(
            f"Cannot read configuration file: {exc}",
            config_path=str(config_path),
        ) from exc

    suffix = config_path.suffix.lower()

    if suffix in (".yaml", ".yml"):
        if not _YAML_AVAILABLE:
            raise ConfigurationError(
                "PyYAML is required for YAML config files. "
                "Install it with: pip install pyyaml",
                config_path=str(config_path),
            )
        try:
            data = yaml.safe_load(raw)  # type: ignore[union-attr]
        except yaml.YAMLError as exc:  # type: ignore[union-attr]
            raise ConfigurationError(
                f"Invalid YAML in config file: {exc}",
                config_path=str(config_path),
            ) from exc
    elif suffix == ".json":
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ConfigurationError(
                f"Invalid JSON in config file: {exc}",
                config_path=str(config_path),
            ) from exc
    else:
        # Try YAML first, then JSON
        if _YAML_AVAILABLE:
            try:
                data = yaml.safe_load(raw)  # type: ignore[union-attr]
            except yaml.YAMLError:  # type: ignore[union-attr]
                try:
                    data = json.loads(raw)
                except json.JSONDecodeError as exc:
                    raise ConfigurationError(
                        f"Cannot parse config file as YAML or JSON: {exc}",
                        config_path=str(config_path),
                    ) from exc
        else:
            try:
                data = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ConfigurationError(
                    f"Cannot parse config file as JSON: {exc}",
                    config_path=str(config_path),
                ) from exc

    if not isinstance(data, dict):
        raise ConfigurationError(
            "Configuration file must contain a mapping at the top level",
            config_path=str(config_path),
        )

    return ScanConfig.from_dict(data)


def default_config() -> ScanConfig:
    """Return a ScanConfig with all default values.

    This is the config used when no configuration file is provided.
    It is deterministic and fully reproducible.
    """
    return ScanConfig()
