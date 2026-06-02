"""Shared pytest fixtures for MythGuardAI tests."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from mythguardai.engine.contract import ContractExtractor
from mythguardai.engine.scanner import MythGuardScanner
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


# ---------------------------------------------------------------------------
# Sample Python code strings for testing
# ---------------------------------------------------------------------------

SUBPROCESS_CODE = '''
import subprocess

def run_command(cmd: str) -> str:
    """Execute a shell command and return output."""
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout
'''

FILE_WRITE_CODE = '''
def save_data(path: str, data: str) -> None:
    """Save data to a file."""
    with open(path, "w") as f:
        f.write(data)
'''

FILE_READ_CODE = '''
def read_data(path: str) -> str:
    """Read data from a file."""
    with open(path, "r") as f:
        return f.read()
'''

NETWORK_CODE = '''
import requests

def fetch_url(url: str) -> str:
    """Fetch content from a URL."""
    response = requests.get(url)
    return response.text
'''

EVAL_EXEC_CODE = '''
def run_dynamic(code: str) -> None:
    """Execute dynamic code."""
    eval(code)
    exec(code)
'''

PRIVILEGE_CODE = '''
import os

def change_permissions(path: str, mode: int) -> None:
    """Change file permissions."""
    os.chmod(path, mode)
    os.setuid(0)
'''

ENVIRONMENT_CODE = '''
import os

def get_config(key: str) -> str:
    """Read an environment variable."""
    return os.environ.get(key, "")
'''

LANGCHAIN_FILE_SEARCH_CODE = '''
"""LangChain file search utility."""

import subprocess

def file_search(query: str, directory: str) -> str:
    """Search for files matching a query in a directory.

    This function uses the system find command to locate files.
    """
    result = subprocess.run(
        ["find", directory, "-name", query],
        capture_output=True,
        text=True,
    )
    return result.stdout
'''

MIXED_INTENT_CODE = '''
"""Module with mixed intents."""

import subprocess
import os

def compute_hash(data: str) -> str:
    """Compute a hash of the data."""
    import hashlib
    return hashlib.sha256(data.encode()).hexdigest()

def run_task(cmd: str) -> None:
    """Run a background task."""
    subprocess.Popen(cmd, shell=True)

def get_env(key: str) -> str:
    """Get environment variable."""
    return os.getenv(key, "")
'''

CLEAN_CODE = '''
def add_numbers(a: int, b: int) -> int:
    """Add two numbers together."""
    return a + b
'''

EMPTY_CODE = ""

GENERIC_NAME_CODE = '''
def process(data):
    return data
'''

NO_DOCSTRING_CODE = '''
def fetch_something(url):
    import requests
    return requests.get(url)
'''


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_subprocess_code() -> str:
    """Python code that uses subprocess."""
    return SUBPROCESS_CODE


@pytest.fixture
def sample_file_write_code() -> str:
    """Python code that writes to files."""
    return FILE_WRITE_CODE


@pytest.fixture
def sample_file_read_code() -> str:
    """Python code that reads from files."""
    return FILE_READ_CODE


@pytest.fixture
def sample_network_code() -> str:
    """Python code that makes network requests."""
    return NETWORK_CODE


@pytest.fixture
def sample_eval_exec_code() -> str:
    """Python code that uses eval/exec."""
    return EVAL_EXEC_CODE


@pytest.fixture
def sample_privilege_code() -> str:
    """Python code that performs privilege operations."""
    return PRIVILEGE_CODE


@pytest.fixture
def sample_environment_code() -> str:
    """Python code that accesses environment variables."""
    return ENVIRONMENT_CODE


@pytest.fixture
def sample_langchain_code() -> str:
    """LangChain file_search.py example code."""
    return LANGCHAIN_FILE_SEARCH_CODE


@pytest.fixture
def sample_mixed_code() -> str:
    """Python code with mixed intents."""
    return MIXED_INTENT_CODE


@pytest.fixture
def sample_clean_code() -> str:
    """Clean Python code with no deviations."""
    return CLEAN_CODE


@pytest.fixture
def sample_empty_code() -> str:
    """Empty Python code string."""
    return EMPTY_CODE


@pytest.fixture
def sample_generic_name_code() -> str:
    """Python code with generic function names."""
    return GENERIC_NAME_CODE


@pytest.fixture
def sample_no_docstring_code() -> str:
    """Python code with no docstring."""
    return NO_DOCSTRING_CODE


@pytest.fixture
def tmp_dir() -> Path:
    """Provide a temporary directory that is cleaned up after the test."""
    with tempfile.TemporaryDirectory() as td:
        yield Path(td)


@pytest.fixture
def tmp_python_file(tmp_dir: Path) -> Path:
    """Create a temporary Python file with sample code and return its path."""
    file_path = tmp_dir / "sample.py"
    file_path.write_text(SUBPROCESS_CODE, encoding="utf-8")
    return file_path


@pytest.fixture
def scanner() -> MythGuardScanner:
    """Provide a MythGuardScanner instance with default configuration."""
    return MythGuardScanner()


@pytest.fixture
def policy_engine() -> PolicyEngine:
    """Provide a PolicyEngine instance with built-in policies."""
    return PolicyEngine()


@pytest.fixture
def contract_extractor() -> ContractExtractor:
    """Provide a ContractExtractor instance."""
    return ContractExtractor()


@pytest.fixture
def sample_contract() -> SemanticContract:
    """Provide a sample SemanticContract for testing."""
    return SemanticContract(
        name="read_config",
        source="config.py",
        declared_intents={IntentCategory.FILE_READ},
        docstring="Read configuration from a file.",
        type_annotations={"path": "Path"},
        decorators=[],
        location=SourceLocation(file="config.py", line=10, col=0, end_line=15, end_col=30),
        confidence=1.0,
    )


@pytest.fixture
def sample_capability() -> Capability:
    """Provide a sample Capability for testing."""
    return Capability(
        category=CapabilityCategory.SUBPROCESS,
        description="Subprocess execution via subprocess.run",
        evidence="subprocess.run",
        location=SourceLocation(file="config.py", line=12, col=4, end_line=12, end_col=30),
        reachability=ReachabilityStatus.REACHABLE,
        confidence=0.9,
    )


@pytest.fixture
def sample_deviation(sample_contract: SemanticContract, sample_capability: Capability) -> Deviation:
    """Provide a sample Deviation for testing."""
    return Deviation(
        contract=sample_contract,
        capability=sample_capability,
        severity=DeviationSeverity.HIGH,
        rule_id="MG-SUB-001",
        message="'read_config' does not declare subprocess intent but contains subprocess capability",
        reachability=ReachabilityStatus.REACHABLE,
        location=SourceLocation(file="config.py", line=12, col=4),
    )


@pytest.fixture
def sample_scan_result(sample_deviation: Deviation) -> ScanResult:
    """Provide a sample ScanResult for testing."""
    result = ScanResult(
        target="config.py",
        deviations=[sample_deviation],
        contracts=[sample_deviation.contract],  # type: ignore[list-item]
        capabilities=[sample_deviation.capability],  # type: ignore[list-item]
        duration_ms=42.5,
        metadata={"scanner_version": "0.1.0"},
    )
    result.compute_risk_score()
    return result


@pytest.fixture
def empty_scan_result() -> ScanResult:
    """Provide a ScanResult with no deviations."""
    result = ScanResult(target="clean.py")
    result.compute_risk_score()
    return result
