"""Tests for the ContractExtractor.

Covers: intent extraction from function names, docstrings, type hints,
decorators, heuristic inference, and edge cases.
"""

from __future__ import annotations

import ast

import pytest

from mythguardai.engine.contract import ContractExtractor
from mythguardai.models import IntentCategory


class TestExtractIntentFromFunctionName:
    """Tests for extracting intent from function names."""

    def test_read_in_name(self, contract_extractor: ContractExtractor) -> None:
        code = "def read_file(path): pass"
        tree = ast.parse(code)
        func = tree.body[0]
        contract = contract_extractor.extract_from_function(func)
        assert IntentCategory.FILE_READ in contract.declared_intents

    def test_write_in_name(self, contract_extractor: ContractExtractor) -> None:
        code = "def write_data(path, data): pass"
        tree = ast.parse(code)
        func = tree.body[0]
        contract = contract_extractor.extract_from_function(func)
        assert IntentCategory.FILE_WRITE in contract.declared_intents

    def test_fetch_in_name_signals_network(self, contract_extractor: ContractExtractor) -> None:
        code = "def fetch_url(url): pass"
        tree = ast.parse(code)
        func = tree.body[0]
        contract = contract_extractor.extract_from_function(func)
        assert IntentCategory.NETWORK in contract.declared_intents

    def test_execute_in_name_signals_subprocess(self, contract_extractor: ContractExtractor) -> None:
        code = "def execute_command(cmd): pass"
        tree = ast.parse(code)
        func = tree.body[0]
        contract = contract_extractor.extract_from_function(func)
        assert IntentCategory.SUBPROCESS in contract.declared_intents

    def test_compute_in_name_signals_computation(self, contract_extractor: ContractExtractor) -> None:
        code = "def compute_hash(data): pass"
        tree = ast.parse(code)
        func = tree.body[0]
        contract = contract_extractor.extract_from_function(func)
        assert IntentCategory.COMPUTATION in contract.declared_intents

    def test_encrypt_in_name_signals_crypto(self, contract_extractor: ContractExtractor) -> None:
        code = "def encrypt_data(data, key): pass"
        tree = ast.parse(code)
        func = tree.body[0]
        contract = contract_extractor.extract_from_function(func)
        assert IntentCategory.CRYPTO in contract.declared_intents

    def test_chmod_in_name_signals_privilege(self, contract_extractor: ContractExtractor) -> None:
        code = "def chmod_file(path, mode): pass"
        tree = ast.parse(code)
        func = tree.body[0]
        contract = contract_extractor.extract_from_function(func)
        assert IntentCategory.PRIVILEGE in contract.declared_intents

    def test_eval_in_name_signals_dynamic_exec(self, contract_extractor: ContractExtractor) -> None:
        code = "def eval_expression(expr): pass"
        tree = ast.parse(code)
        func = tree.body[0]
        contract = contract_extractor.extract_from_function(func)
        assert IntentCategory.DYNAMIC_EXEC in contract.declared_intents

    def test_query_in_name_signals_database(self, contract_extractor: ContractExtractor) -> None:
        code = "def query_db(sql): pass"
        tree = ast.parse(code)
        func = tree.body[0]
        contract = contract_extractor.extract_from_function(func)
        assert IntentCategory.DATABASE in contract.declared_intents

    def test_serialize_in_name(self, contract_extractor: ContractExtractor) -> None:
        code = "def serialize_object(obj): pass"
        tree = ast.parse(code)
        func = tree.body[0]
        contract = contract_extractor.extract_from_function(func)
        assert IntentCategory.SERIALIZATION in contract.declared_intents


class TestExtractIntentFromDocstring:
    """Tests for extracting intent from docstrings."""

    def test_network_keyword_in_docstring(self, contract_extractor: ContractExtractor) -> None:
        code = '''
def process(data):
    """Send data over the network."""
    pass
'''
        tree = ast.parse(code)
        func = tree.body[0]
        contract = contract_extractor.extract_from_function(func)
        assert IntentCategory.NETWORK in contract.declared_intents

    def test_subprocess_keyword_in_docstring(self, contract_extractor: ContractExtractor) -> None:
        code = '''
def do_work(cmd):
    """Execute a subprocess command."""
    pass
'''
        tree = ast.parse(code)
        func = tree.body[0]
        contract = contract_extractor.extract_from_function(func)
        assert IntentCategory.SUBPROCESS in contract.declared_intents

    def test_read_keyword_in_docstring(self, contract_extractor: ContractExtractor) -> None:
        code = '''
def load_config():
    """Read the configuration file."""
    pass
'''
        tree = ast.parse(code)
        func = tree.body[0]
        contract = contract_extractor.extract_from_function(func)
        assert IntentCategory.FILE_READ in contract.declared_intents

    def test_write_keyword_in_docstring(self, contract_extractor: ContractExtractor) -> None:
        code = '''
def persist_data(data):
    """Write data to disk."""
    pass
'''
        tree = ast.parse(code)
        func = tree.body[0]
        contract = contract_extractor.extract_from_function(func)
        assert IntentCategory.FILE_WRITE in contract.declared_intents

    def test_environment_keyword_in_docstring(self, contract_extractor: ContractExtractor) -> None:
        code = '''
def get_setting(key):
    """Read an environment variable setting."""
    pass
'''
        tree = ast.parse(code)
        func = tree.body[0]
        contract = contract_extractor.extract_from_function(func)
        assert IntentCategory.ENVIRONMENT in contract.declared_intents


class TestExtractIntentFromTypeHints:
    """Tests for extracting intent from type annotations."""

    def test_path_type_hint(self, contract_extractor: ContractExtractor) -> None:
        code = '''
from pathlib import Path

def load_file(path: Path) -> str:
    pass
'''
        tree = ast.parse(code)
        func = tree.body[1]  # skip the import
        contract = contract_extractor.extract_from_function(func)
        assert IntentCategory.FILE_READ in contract.declared_intents

    def test_response_type_hint(self, contract_extractor: ContractExtractor) -> None:
        code = '''
def fetch(url: str) -> Response:
    pass
'''
        tree = ast.parse(code)
        func = tree.body[0]
        contract = contract_extractor.extract_from_function(func)
        assert IntentCategory.NETWORK in contract.declared_intents

    def test_completed_process_type_hint(self, contract_extractor: ContractExtractor) -> None:
        code = '''
def run_cmd(cmd: str) -> CompletedProcess:
    pass
'''
        tree = ast.parse(code)
        func = tree.body[0]
        contract = contract_extractor.extract_from_function(func)
        assert IntentCategory.SUBPROCESS in contract.declared_intents

    def test_type_annotations_captured(self, contract_extractor: ContractExtractor) -> None:
        code = '''
def fetch(url: str) -> Response:
    pass
'''
        tree = ast.parse(code)
        func = tree.body[0]
        contract = contract_extractor.extract_from_function(func)
        assert "url" in contract.type_annotations
        assert "return" in contract.type_annotations


class TestExtractIntentFromDecorators:
    """Tests for extracting intent from decorators."""

    def test_app_route_decorator(self, contract_extractor: ContractExtractor) -> None:
        code = '''
@app.route("/api")
def api_endpoint():
    pass
'''
        tree = ast.parse(code)
        func = tree.body[0]
        contract = contract_extractor.extract_from_function(func)
        assert IntentCategory.NETWORK in contract.declared_intents

    def test_login_required_decorator(self, contract_extractor: ContractExtractor) -> None:
        code = '''
@login_required
def admin_panel():
    pass
'''
        tree = ast.parse(code)
        func = tree.body[0]
        contract = contract_extractor.extract_from_function(func)
        assert IntentCategory.PRIVILEGE in contract.declared_intents

    def test_decorator_list_captured(self, contract_extractor: ContractExtractor) -> None:
        code = '''
@app.route("/api")
@login_required
def protected_api():
    pass
'''
        tree = ast.parse(code)
        func = tree.body[0]
        contract = contract_extractor.extract_from_function(func)
        assert len(contract.decorators) == 2


class TestHeuristicIntentInference:
    """Tests for fallback heuristic intent inference."""

    def test_underscore_split_name(self, contract_extractor: ContractExtractor) -> None:
        code = "def send_http_request(url): pass"
        tree = ast.parse(code)
        func = tree.body[0]
        contract = contract_extractor.extract_from_function(func)
        # "send" and "request" both signal NETWORK
        assert IntentCategory.NETWORK in contract.declared_intents

    def test_multiple_intents_from_name(self, contract_extractor: ContractExtractor) -> None:
        code = "def write_and_send_data(data): pass"
        tree = ast.parse(code)
        func = tree.body[0]
        contract = contract_extractor.extract_from_function(func)
        assert IntentCategory.FILE_WRITE in contract.declared_intents
        assert IntentCategory.NETWORK in contract.declared_intents


class TestEdgeCases:
    """Tests for edge cases in contract extraction."""

    def test_no_docstring(self, contract_extractor: ContractExtractor) -> None:
        code = "def compute(x, y): pass"
        tree = ast.parse(code)
        func = tree.body[0]
        contract = contract_extractor.extract_from_function(func)
        # "compute" keyword maps to COMPUTATION intent
        assert IntentCategory.COMPUTATION in contract.declared_intents
        assert contract.docstring is None

    def test_generic_name_defaults_to_computation(self, contract_extractor: ContractExtractor) -> None:
        code = "def process(data): pass"
        tree = ast.parse(code)
        func = tree.body[0]
        contract = contract_extractor.extract_from_function(func)
        # "process" is in the name map, so COMPUTATION is from name
        assert IntentCategory.COMPUTATION in contract.declared_intents

    def test_completely_generic_name(self, contract_extractor: ContractExtractor) -> None:
        code = "def do_stuff(x): pass"
        tree = ast.parse(code)
        func = tree.body[0]
        contract = contract_extractor.extract_from_function(func)
        # No name match, no docstring: defaults to COMPUTATION
        assert IntentCategory.COMPUTATION in contract.declared_intents
        assert contract.confidence == 0.5  # No name or docstring signals

    def test_confidence_high_with_name_match(self, contract_extractor: ContractExtractor) -> None:
        code = "def read_file(path): pass"
        tree = ast.parse(code)
        func = tree.body[0]
        contract = contract_extractor.extract_from_function(func)
        assert contract.confidence == 1.0

    def test_confidence_reduced_with_docstring_only(self, contract_extractor: ContractExtractor) -> None:
        code = '''
def helper(x):
    """Read the configuration from network."""
    pass
'''
        tree = ast.parse(code)
        func = tree.body[0]
        contract = contract_extractor.extract_from_function(func)
        # Name "helper" has no match, so intent comes from docstring
        assert contract.confidence == 0.8

    def test_location_populated(self, contract_extractor: ContractExtractor) -> None:
        code = "def my_func(): pass"
        tree = ast.parse(code)
        func = tree.body[0]
        contract = contract_extractor.extract_from_function(func)
        assert contract.location is not None
        assert contract.location.line == 1

    def test_class_extraction(self, contract_extractor: ContractExtractor) -> None:
        code = '''
class FileReader:
    """Read files from disk."""
    pass
'''
        tree = ast.parse(code)
        cls = tree.body[0]
        contract = contract_extractor.extract_from_class(cls)
        assert contract.name == "FileReader"
        # "read" is in the class name
        assert IntentCategory.FILE_READ in contract.declared_intents

    def test_module_extraction(self, contract_extractor: ContractExtractor) -> None:
        code = '''
"""Network utility module."""

import requests
'''
        tree = ast.parse(code)
        contract = contract_extractor.extract_from_module(tree)
        assert IntentCategory.NETWORK in contract.declared_intents

    def test_async_function(self, contract_extractor: ContractExtractor) -> None:
        code = "async def fetch_data(url): pass"
        tree = ast.parse(code)
        func = tree.body[0]
        contract = contract_extractor.extract_from_function(func)
        assert contract.name == "fetch_data"
        assert IntentCategory.NETWORK in contract.declared_intents

    def test_set_source_file(self, contract_extractor: ContractExtractor) -> None:
        contract_extractor.set_source_file("custom_module.py")
        code = "def my_func(): pass"
        tree = ast.parse(code)
        func = tree.body[0]
        contract = contract_extractor.extract_from_function(func)
        assert contract.source == "custom_module.py"
        assert contract.location is not None
        assert contract.location.file == "custom_module.py"
