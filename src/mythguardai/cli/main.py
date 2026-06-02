"""MythGuardAI CLI - Click-based command-line interface.

Provides commands for scanning code, analyzing files, listing policies,
and checking policy compliance. Uses Rich for terminal output with
tables and colors.

Commands:
    mythguardai scan <path> - Scan a file or directory
    mythguardai analyze <file> - Analyze a single file
    mythguardai policy list - List all registered policies
    mythguardai policy check <path> - Check a path against policies
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import click

from mythguardai.config import ScanConfig, default_config, load_config
from mythguardai.engine.scanner import MythGuardScanner
from mythguardai.exceptions import MythGuardError
from mythguardai.models import DeviationSeverity, ScanResult
from mythguardai.policies.policy_engine import PolicyEngine
from mythguardai.reporters.json_reporter import JsonReporter
from mythguardai.reporters.markdown_reporter import MarkdownReporter
from mythguardai.reporters.sarif_reporter import SarifReporter

# Try to import Rich for enhanced terminal output
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text

    _RICH_AVAILABLE = True
except ImportError:  # pragma: no cover
    _RICH_AVAILABLE = False

# Severity color mapping for Rich
_SEVERITY_STYLES: dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "blue",
}


def _get_console() -> Any:
    """Get a Rich Console instance, or None if Rich is unavailable."""
    if _RICH_AVAILABLE:
        return Console()
    return None


def _get_reporter(fmt: str) -> JsonReporter | MarkdownReporter | SarifReporter:
    """Get the appropriate reporter for the output format."""
    if fmt == "json":
        return JsonReporter()
    elif fmt == "markdown":
        return MarkdownReporter()
    elif fmt == "sarif":
        return SarifReporter()
    else:
        raise click.BadParameter(f"Unsupported format: {fmt}")


def _print_rich_result(console: Any, result: ScanResult) -> None:
    """Print a scan result using Rich formatting."""
    if not _RICH_AVAILABLE or console is None:
        return

    # Header panel
    console.print(
        Panel(
            f"[bold]MythGuardAI Scan Result[/bold]\n"
            f"Target: {result.target}\n"
            f"Scan ID: {result.scan_id}\n"
            f"Duration: {result.duration_ms:.1f} ms",
            title="Scan Summary",
        )
    )

    # Risk score
    score = result.risk_score
    grade_style = "green" if score.grade in ("A", "B") else "yellow" if score.grade == "C" else "red"

    console.print(
        f"\nRisk Score: [{grade_style}]{score.total}/100 (Grade: {score.grade})[/{grade_style}]"
    )

    # Severity summary table
    summary_table = Table(title="Severity Breakdown")
    summary_table.add_column("Severity", style="bold")
    summary_table.add_column("Count", justify="right")

    summary_table.add_row("CRITICAL", str(score.critical_count), style="bold red")
    summary_table.add_row("HIGH", str(score.high_count), style="red")
    summary_table.add_row("MEDIUM", str(score.medium_count), style="yellow")
    summary_table.add_row("LOW", str(score.low_count), style="blue")

    console.print(summary_table)

    # Deviations table
    if result.deviations:
        dev_table = Table(title="Deviations")
        dev_table.add_column("Rule", style="cyan")
        dev_table.add_column("Severity", style="bold")
        dev_table.add_column("Contract", style="green")
        dev_table.add_column("Evidence", style="magenta")
        dev_table.add_column("Location")
        dev_table.add_column("Reachability")

        for dev in result.deviations:
            severity = dev.severity.value
            style = _SEVERITY_STYLES.get(severity, "white")
            contract_name = dev.contract.name if dev.contract else "N/A"
            evidence = dev.capability.evidence if dev.capability else "N/A"
            location = (
                f"{dev.location.file}:{dev.location.line}"
                if dev.location
                else "N/A"
            )
            dev_table.add_row(
                dev.rule_id,
                f"[{style}]{severity}[/{style}]",
                contract_name,
                evidence,
                location,
                dev.reachability.value,
            )

        console.print(dev_table)
    else:
        console.print("\n[green]No deviations found. All capabilities align with declared intent.[/green]")


def _print_plain_result(result: ScanResult) -> None:
    """Print a scan result in plain text (no Rich)."""
    score = result.risk_score
    click.echo(f"Scan Result: {result.target}")
    click.echo(f"Risk Score: {score.total}/100 (Grade: {score.grade})")
    click.echo(f"Deviations: {len(result.deviations)}")
    click.echo(
        f"  CRITICAL: {score.critical_count}  HIGH: {score.high_count}  "
        f"MEDIUM: {score.medium_count}  LOW: {score.low_count}"
    )
    click.echo("")

    if result.deviations:
        for dev in result.deviations:
            contract_name = dev.contract.name if dev.contract else "N/A"
            evidence = dev.capability.evidence if dev.capability else "N/A"
            location = (
                f"{dev.location.file}:{dev.location.line}"
                if dev.location
                else "N/A"
            )
            click.echo(
                f"[{dev.severity.value}] {dev.rule_id}: {dev.message}"
            )
            click.echo(f"  Contract: {contract_name}, Evidence: {evidence}")
            click.echo(f"  Location: {location}, Reachability: {dev.reachability.value}")
            click.echo("")
    else:
        click.echo("No deviations found.")


# ---------------------------------------------------------------------------
# CLI Group
# ---------------------------------------------------------------------------


@click.group()
@click.version_option(version="0.1.0", prog_name="mythguardai")
def cli() -> None:
    """MythGuardAI: Semantic Application Security for the AI Era.

    Detect capability drift by comparing declared intent vs reachable
    capability. Deterministic, offline-capable, fully auditable.
    """
    pass


# ---------------------------------------------------------------------------
# scan command
# ---------------------------------------------------------------------------


@cli.command()
@click.argument("path", type=click.Path(exists=True))
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["json", "markdown", "sarif"]),
    default="json",
    help="Output format.",
)
@click.option(
    "--severity-threshold",
    type=click.Choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
    default="LOW",
    help="Minimum severity to report.",
)
@click.option(
    "--output",
    "output_path",
    type=click.Path(),
    default=None,
    help="Write output to file instead of stdout.",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True),
    default=None,
    help="Path to configuration file.",
)
def scan(
    path: str,
    output_format: str,
    severity_threshold: str,
    output_path: str | None,
    config_path: str | None,
) -> None:
    """Scan a file or directory for capability drift.

    PATH is the file or directory to scan.
    """
    try:
        # Load configuration
        if config_path:
            scan_config = load_config(config_path)
        else:
            scan_config = default_config()

        # Override with CLI options
        scan_config.severity_threshold = DeviationSeverity(severity_threshold)
        scan_config.output_format = output_format
        if output_path:
            scan_config.output_path = output_path

        # Run scan
        scanner = MythGuardScanner(config=scan_config)
        result = scanner.scan_path(path)
        result.compute_risk_score()

        # Output
        if output_format == "json" and output_path is None:
            # If no output file and format is JSON, use rich/plain display
            console = _get_console()
            if console:
                _print_rich_result(console, result)
            else:
                _print_plain_result(result)
            click.echo("\n--- JSON Output ---\n")
            reporter = JsonReporter()
            click.echo(reporter.render(result))
        else:
            reporter = _get_reporter(output_format)
            output = reporter.render(result)
            if output_path:
                reporter.render_to_file(result, output_path)
                click.echo(f"Results written to {output_path}")
            else:
                click.echo(output)

        # Exit code
        if scan_config.fail_on_critical and result.has_critical:
            sys.exit(1)

    except MythGuardError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(2)
    except Exception as exc:
        click.echo(f"Unexpected error: {exc}", err=True)
        sys.exit(3)


# ---------------------------------------------------------------------------
# analyze command
# ---------------------------------------------------------------------------


@cli.command()
@click.argument("file", type=click.Path(exists=True))
@click.option(
    "--language",
    type=click.Choice(["python", "javascript"]),
    default=None,
    help="Language (auto-detected if not specified).",
)
def analyze(file: str, language: str | None) -> None:
    """Analyze a single file and show capabilities.

    FILE is the path to the source file to analyze.
    """
    try:
        scan_config = default_config()

        if language is None:
            language = scan_config.detect_language(file)
            if language is None:
                click.echo(
                    f"Cannot detect language for {file}. "
                    "Specify --language explicitly.",
                    err=True,
                )
                sys.exit(2)

        scanner = MythGuardScanner(config=scan_config)
        result = scanner.scan_file(file)

        console = _get_console()
        if console:
            _print_rich_result(console, result)
        else:
            _print_plain_result(result)

    except MythGuardError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(2)
    except Exception as exc:
        click.echo(f"Unexpected error: {exc}", err=True)
        sys.exit(3)


# ---------------------------------------------------------------------------
# policy group
# ---------------------------------------------------------------------------


@cli.group()
def policy() -> None:
    """Manage and inspect security policies."""
    pass


@policy.command("list")
def policy_list() -> None:
    """List all registered security policies."""
    engine = PolicyEngine()
    policies = engine.list_policies()

    console = _get_console()

    if console:
        table = Table(title="Registered Policies")
        table.add_column("Rule ID", style="cyan")
        table.add_column("Description")

        for p in policies:
            table.add_row(p["rule_id"], p["description"])

        console.print(table)
    else:
        click.echo("Registered Policies:")
        click.echo("-" * 60)
        for p in policies:
            click.echo(f"  {p['rule_id']}: {p['description']}")


@policy.command("check")
@click.argument("path", type=click.Path(exists=True))
@click.option(
    "--policy-dir",
    type=click.Path(exists=True),
    multiple=True,
    help="Directory containing custom policy modules.",
)
def policy_check(path: str, policy_dir: tuple[str, ...]) -> None:
    """Check a path against all registered policies.

    PATH is the file or directory to check.
    """
    try:
        scan_config = default_config()
        for d in policy_dir:
            scan_config.policy_dirs.append(d)

        scanner = MythGuardScanner(config=scan_config)
        result = scanner.scan_path(path)
        result.compute_risk_score()

        console = _get_console()
        if console:
            _print_rich_result(console, result)
        else:
            _print_plain_result(result)

        if result.has_critical:
            sys.exit(1)

    except MythGuardError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(2)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Entry point for the MythGuardAI CLI."""
    cli()


if __name__ == "__main__":
    main()
