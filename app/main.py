import argparse

from app.services.threat_service import ThreatService
from app.ui.dashboard import show_vulnerabilities
from app.ui.status_dashboard import show_status


def parse_args():
    parser = argparse.ArgumentParser(description="Threat Intelligence Dashboard")

    parser.add_argument(
        "--severity",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        help="Filter vulnerabilities by severity",
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=25,
        help="Number of latest vulnerabilities to display (default: 25)",
    )

    parser.add_argument(
        "--sync",
        action="store_true",
        help="Synchronize the local database with the NVD API",
    )

    parser.add_argument(
        "--status",
        action="store_true",
        help="Show database statistics",
    )

    return parser.parse_args()


def main():
    args = parse_args()

    service = ThreatService()

    if args.status:
        stats = service.status()
        show_status(stats)
        return

    if args.sync:
        print("Synchronizing with the NVD database...")
        service.sync()

    vulnerabilities = service.get_vulnerabilities(
        severity=args.severity,
    )

    # Display only the requested number of latest CVEs
    show_vulnerabilities(vulnerabilities[: args.limit])


if __name__ == "__main__":
    main()
