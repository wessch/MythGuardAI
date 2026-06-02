# Contributing to MythGuardAI

Thank you for your interest in contributing to MythGuardAI. This document provides guidelines and instructions for contributing.

## Code of Conduct

All contributors are expected to follow our [Code of Conduct](CODE_OF_CONDUCT.md). Please read it before participating.

## How to Contribute

### Reporting Issues

1. Check existing issues to avoid duplicates.
2. Open a new issue with a clear title and description.
3. Include steps to reproduce, expected behavior, and actual behavior.
4. For security-related findings, follow our [Security Policy](SECURITY.md) instead of opening a public issue.

### Suggesting Features

1. Open an issue with the prefix `[Feature]` in the title.
2. Describe the problem the feature solves, not just the proposed solution.
3. Explain how the feature aligns with MythGuardAI's core mission: detecting semantic deviation between declared intent and reachable capability.

### Submitting Code

1. Fork the repository.
2. Create a feature branch from `main`: `git checkout -b feature/your-feature-name`
3. Make your changes with clear, atomic commits.
4. Add or update tests for your changes.
5. Ensure all tests pass: `pytest`
6. Ensure type checking passes: `mypy src/`
7. Ensure linting passes: `ruff check src/ tests/`
8. Push your branch and open a pull request against `main`.

## Development Setup

### Prerequisites

- Python 3.10 or later
- Git

### Installation

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/MythGuardAI.git
cd MythGuardAI

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate   # Windows

# Install with dev dependencies
pip install -e ".[dev]"

# Verify installation
mythguardai --help
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=mythguardai --cov-report=term-missing

# Run specific test file
pytest tests/test_scanner.py
```

### Type Checking

```bash
mypy src/
```

### Linting

```bash
# Check for issues
ruff check src/ tests/

# Auto-fix issues
ruff check --fix src/ tests/
```

## Coding Standards

### Style

- Follow PEP 8 as enforced by Ruff.
- Maximum line length: 88 characters.
- Use type hints for all function signatures.
- Write docstrings for all public modules, classes, and functions.

### Commit Messages

- Use the imperative mood: "Add feature" not "Added feature".
- Keep the first line under 72 characters.
- Reference issues when applicable: "Fix capability extraction for nested imports (#42)".

### Testing

- Every new feature must include tests.
- Every bug fix must include a regression test.
- Aim for meaningful coverage, not percentage targets.
- Tests should be deterministic and not depend on external services.

### Semantic Analysis Contributions

When contributing to the core analysis engine:

1. Ensure all findings are traceable to a concrete code path.
2. Never introduce heuristic-based detection without documenting the heuristic and its known limitations.
3. Maintain determinism: same input must always produce the same output.
4. Preserve offline capability: no network calls during analysis.

## Pull Request Process

1. Ensure your PR has a clear description of the change and motivation.
2. Link to any relevant issues.
3. Ensure CI passes (tests, type checking, linting).
4. Be responsive to review feedback.
5. Squash commits if requested during review.

## Questions?

Open an issue with the prefix `[Question]` or reach out to info@mythguardai.com.
