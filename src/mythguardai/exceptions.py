"""Custom exceptions for MythGuardAI.

All MythGuardAI exceptions inherit from MythGuardError, enabling
catch-all handling while preserving granularity for specific failure modes.
"""


class MythGuardError(Exception):
    """Base exception for all MythGuardAI errors.

    Every exception raised by MythGuardAI inherits from this class,
    allowing callers to catch the entire hierarchy with a single
    ``except MythGuardError`` clause.
    """

    def __init__(self, message: str, *, details: dict[str, object] | None = None) -> None:
        self.details: dict[str, object] = details or {}
        super().__init__(message)


class ScanError(MythGuardError):
    """Raised when a scan operation fails.

    Covers file-access failures, parse errors, and any other
    problem encountered while scanning a target path or code string.
    """

    def __init__(
        self,
        message: str,
        *,
        path: str | None = None,
        details: dict[str, object] | None = None,
    ) -> None:
        self.path = path
        if path and details is None:
            details = {"path": path}
        elif path and details is not None:
            details = {**details, "path": path}
        super().__init__(message, details=details)


class PolicyError(MythGuardError):
    """Raised when policy evaluation encounters a problem.

    This includes malformed custom policies, conflicting rule
    definitions, or failure to load a policy module.
    """

    def __init__(
        self,
        message: str,
        *,
        policy_name: str | None = None,
        details: dict[str, object] | None = None,
    ) -> None:
        self.policy_name = policy_name
        if policy_name and details is None:
            details = {"policy_name": policy_name}
        elif policy_name and details is not None:
            details = {**details, "policy_name": policy_name}
        super().__init__(message, details=details)


class ConfigurationError(MythGuardError):
    """Raised when the configuration is invalid or incomplete.

    Covers missing required fields, values outside acceptable ranges,
    and unreadable or malformed configuration files.
    """

    def __init__(
        self,
        message: str,
        *,
        config_path: str | None = None,
        details: dict[str, object] | None = None,
    ) -> None:
        self.config_path = config_path
        if config_path and details is None:
            details = {"config_path": config_path}
        elif config_path and details is not None:
            details = {**details, "config_path": config_path}
        super().__init__(message, details=details)


class AnalyzerError(MythGuardError):
    """Raised when an analyzer fails to process its input.

    This typically indicates a problem with the source code being
    analyzed (e.g. syntax errors) or an unsupported language.
    """

    def __init__(
        self,
        message: str,
        *,
        language: str | None = None,
        file_path: str | None = None,
        details: dict[str, object] | None = None,
    ) -> None:
        self.language = language
        self.file_path = file_path
        if details is None:
            details = {}
        if language:
            details["language"] = language
        if file_path:
            details["file_path"] = file_path
        super().__init__(message, details=details)
