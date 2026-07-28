from rich.console import Console
from rich.table import Table

console = Console()


def show_status(stats: dict):
    """Display database statistics."""

    severity = stats["severity"]

    table = Table(title="ThreatIntel Database Status")

    table.add_column("Metric", style="cyan")
    table.add_column("Value", justify="right", style="green")

    table.add_row("Total CVEs", str(stats["total"]))
    table.add_row("Critical", str(severity.get("CRITICAL", 0)))
    table.add_row("High", str(severity.get("HIGH", 0)))
    table.add_row("Medium", str(severity.get("MEDIUM", 0)))
    table.add_row("Low", str(severity.get("LOW", 0)))
    table.add_row("Unknown", str(severity.get("UNKNOWN", 0)))

    console.print(table)