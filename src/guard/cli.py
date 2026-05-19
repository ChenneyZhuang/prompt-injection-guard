"""Command-line interface for prompt injection guard."""

from __future__ import annotations

import argparse
import logging
import sys

from guard.models.schemas import RiskLevel
from guard.pipeline import scan

logger = logging.getLogger(__name__)

LEVEL_COLORS: dict[RiskLevel, str] = {
    RiskLevel.SAFE: "green",
    RiskLevel.LOW: "blue",
    RiskLevel.MEDIUM: "yellow",
    RiskLevel.HIGH: "orange1",
    RiskLevel.CRITICAL: "red",
}


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="guard",
        description="Detect prompt injection attacks in user input.",
    )
    p.add_argument(
        "text",
        nargs="*",
        help="Text to scan for injection (reads from stdin if omitted)",
    )
    p.add_argument(
        "-j",
        "--json",
        action="store_true",
        help="Output result as JSON instead of rich-formatted text",
    )
    p.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable debug logging",
    )
    p.add_argument(
        "--version",
        action="version",
        version="prompt-injection-guard 0.1.0",
    )
    return p


def _format_rich(result) -> str:
    """Return a rich-formatted string for terminal display."""
    try:
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table
    except ImportError:
        return _format_plain(result)

    console = Console()
    color = LEVEL_COLORS.get(result.risk_level, "white")

    # Build output
    lines: list[str] = []

    panel = Panel(
        f"[bold {color}]Risk: {result.risk_level.upper()}[/bold {color}]  (score: {result.score:.2f})",
        title="Prompt Injection Guard",
        border_style=color,
    )
    with console.capture() as capture:
        console.print(panel)
        lines.append(capture.get().rstrip())

    lines.append(f"\n[bold]Reasoning:[/bold] {result.reasoning}")

    if result.patterns_matched:
        lines.append(f"\n[bold]Matched {len(result.patterns_matched)} pattern(s):[/bold]")
        for m in result.patterns_matched:
            lines.append(f"  • {m.name}: {m.description}")
            lines.append(f'    Text: [italic]"{m.matched_text[:80]}"[/italic]')

    if result.safe_alternative:
        lines.append("\n[bold green]Suggested safe alternative:[/bold green]")
        lines.append(f"  {result.safe_alternative}")

    lines.append(f"\n[dim]Detection method: {result.method}[/dim]")
    return "\n".join(lines)


def _format_plain(result) -> str:
    """Plain text output (no rich dependency)."""
    lines = [
        f"Risk Level: {result.risk_level.upper()}",
        f"Score:      {result.score:.2f}",
        f"Method:     {result.method}",
        "",
        f"Reasoning: {result.reasoning}",
    ]
    if result.patterns_matched:
        lines.append(f"\nMatched Patterns ({len(result.patterns_matched)}):")
        for m in result.patterns_matched:
            lines.append(f"  - {m.name}: {m.description}")
    if result.safe_alternative:
        lines.append(f"\nSafe Alternative: {result.safe_alternative}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    """Entry point for the CLI. Returns exit code."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    _setup_logging(args.verbose)

    # Determine input text
    if args.text:
        text = " ".join(args.text)
    else:
        text = sys.stdin.read().strip()

    if not text:
        parser.print_help()
        return 1

    result = scan(text)

    if args.json:
        print(result.model_dump_json(indent=2))
    else:
        try:
            output = _format_rich(result)
        except Exception:
            output = _format_plain(result)
        print(output)

    # Exit with non-zero if high+ risk
    if result.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
