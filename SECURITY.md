# Security Policy

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a vulnerability in MythGuardAI, please report it responsibly.

### Do Not Report Vulnerabilities Via Public GitHub Issues

Instead, please email your findings to **info@mythguardai.com** with the subject line `[Security] Brief Description`.

### What to Include

Please provide as much of the following information as possible:

- **Description**: A clear description of the vulnerability.
- **Impact**: What an attacker could achieve by exploiting this vulnerability.
- **Reproduction**: Step-by-step instructions to reproduce the issue.
- **Proof of Concept**: Code, commands, or screenshots that demonstrate the vulnerability.
- **Affected Versions**: Which versions of MythGuardAI are affected.
- **Suggested Fix**: If you have ideas for how to remediate the issue.

### Response Timeline

| Stage | Target Time |
|---|---|
| Acknowledgment of report | Within 48 hours |
| Initial assessment and triage | Within 5 business days |
| Status update to reporter | Within 10 business days |
| Remediation or mitigation | Depends on severity and complexity |

### Severity Classification

We use the following severity levels:

- **Critical**: Remote code execution, data exfiltration, or complete system compromise via MythGuardAI.
- **High**: Significant security bypass, privilege escalation, or data exposure.
- **Medium**: Limited security impact, such as denial of service or information leakage.
- **Low**: Minor issues with minimal security impact.

### Responsible Disclosure Guidelines

- Do not access or modify other users' data without permission.
- Do not degrade system performance or availability.
- Do not publicly disclose the vulnerability before a fix is released.
- Provide reasonable time for remediation before public disclosure (minimum 90 days).
- We will credit researchers who report vulnerabilities responsibly, unless you prefer to remain anonymous.

### Out of Scope

The following are not considered security vulnerabilities:

- Theoretical issues without a practical attack scenario.
- Issues in dependencies that are already patched in the latest version.
- Denial of service via extremely large input (resource exhaustion).
- Social engineering attacks.
- Issues in development or test configurations.

## Security Architecture

MythGuardAI is designed with the following security principles:

- **Offline by default**: No network calls during analysis. Your code never leaves your machine.
- **Deterministic analysis**: Same input always produces the same output. No hidden state.
- **No telemetry**: Zero data collection. No phone-home, no analytics, no tracking.
- **Minimal permissions**: The analysis engine only reads files. It does not execute the code it analyzes.
- **Auditable findings**: Every security finding links to a concrete, reproducible evidence chain.

## Supported Versions

| Version | Supported |
|---|---|
| 0.1.x | Yes |
| < 0.1.0 | No |

As MythGuardAI is in early development, only the latest release is actively supported for security updates.
