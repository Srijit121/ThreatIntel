from rich.console import Console
from rich.table import Table
from rich.text import Text

console = Console()


def severity_colour(severity: str | None) -> str:
    """Return the Rich colour for a severity level."""

    colours = {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "green",
    }

    return colours.get((severity or "UNKNOWN").upper(), "white")


def show_vulnerabilities(vulnerabilities):
    """Display vulnerability information."""

    table = Table(
        show_header=True,
        header_style="bold cyan",
    )

    table.add_column("CVE", style="cyan", no_wrap=True)
    table.add_column("Severity", justify="center")
    table.add_column("CVSS", justify="center")
    table.add_column("KEV", justify="center", style="bold red")
    table.add_column("Vendor", overflow="fold")
    table.add_column("Product", overflow="fold")
    table.add_column("Published")

    for cve in vulnerabilities:

        severity = Text(
            cve.severity or "UNKNOWN",
            style=severity_colour(cve.severity),
        )

        kev = "✅ YES" if cve.kev else ""

        table.add_row(
            cve.id,
            severity,
            f"{cve.cvss_score:.1f}" if cve.cvss_score is not None else "-",
            kev,
            cve.vendor or "-",
            cve.product or "-",
            cve.published[:10] if cve.published else "-",
        )

    console.print(table)
