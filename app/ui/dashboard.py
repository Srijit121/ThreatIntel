from rich.console import Console
from rich.table import Table
from rich.text import Text

console = Console()


def severity_colour(severity: str) -> str:
    colours = {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "green",
    }
    return colours.get(severity.upper(), "white")


def show_vulnerabilities(vulnerabilities):
    table = Table(
        title="Threat Intelligence Dashboard",
        show_lines=True,
        header_style="bold cyan",
    )

    table.add_column("CVE", style="cyan", no_wrap=True)
    table.add_column("Severity", justify="center")
    table.add_column("Published", style="green")
    table.add_column("Description")

    for cve in vulnerabilities:
        severity = Text(
            cve.severity,
            style=severity_colour(cve.severity),
        )

        description = (
            cve.description[:70] + "..."
            if len(cve.description) > 70
            else cve.description
        )

        table.add_row(
            cve.id,
            severity,
            cve.published[:10],
            description,
        )

    console.print(table)