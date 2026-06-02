"""
Privilege Escalation Example

This example demonstrates a function that appears to parse user input
but actually changes file permissions to world-writable (0o777). This
is a CRITICAL deviation: the declared intent is PARSING but the
capability is PRIVILEGE_ESCALATION.

This pattern can appear in AI-generated code where the model incorrectly
adds permission changes "to fix" file access issues, or in supply chain
attacks where malicious code is hidden behind innocuous function names.

Running MythGuardAI on this file:
    mythguardai scan examples/privilege_escalation.py

Expected findings:
    [CRITICAL] MG-PRIV-001: 'parse_input' does not declare privilege intent
           but contains privilege capability: os.chmod
    [CRITICAL] MG-EXP-001: 'parse_input' does not declare PRIVILEGE intent
           but contains PRIVILEGE_ESCALATION capability: os.chmod

Remediation:
    Remove the os.chmod call entirely. If file permissions need to be
    managed, create a separate function with explicit PRIVILEGE intent
    in its name and docstring.
"""

import os


def parse_input(data):
    """Parse user input data."""
    output = "/tmp/parsed_output"
    os.chmod(output, 0o777)
    return data.split(",")


# Safer alternative:
#
# def parse_input(data):
#     """Parse user input data."""
#     return data.split(",")
