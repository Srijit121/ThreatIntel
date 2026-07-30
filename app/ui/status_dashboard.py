from rich.console import Console
from rich.table import Table

console = Console()


def show_status(stats):
    """Display database status."""

    severity = stats["severity"]

    table = Table(title="ThreatIntel Database Status")

    table.add_column("Metric", style="cyan")
    table.add_column("Value", justify="right", style="green")

    table.add_row(
        "Last Sync",
        stats.get("last_sync") or "Never",
    )

    table.add_row(
        "Total CVEs",
        str(stats["total"]),
    )

    table.add_row(
        "Critical",
        str(severity.get("CRITICAL", 0)),
    )

    table.add_row(
        "High",
        str(severity.get("HIGH", 0)),
    )

    table.add_row(
        "Medium",
        str(severity.get("MEDIUM", 0)),
    )

    table.add_row(
        "Low",
        str(severity.get("LOW", 0)),
    )

    table.add_row(
        "Unknown",
        str(severity.get("UNKNOWN", 0)),
    )

    console.print(table)
