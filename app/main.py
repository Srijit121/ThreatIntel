import argparse

from app.services.threat_service import ThreatService
from app.ui.dashboard import show_vulnerabilities


def parse_args():
    parser = argparse.ArgumentParser(
        description="Threat Intelligence Dashboard"
    )

    parser.add_argument(
        "--severity",
        choices=[
            "LOW",
            "MEDIUM",
            "HIGH",
            "CRITICAL",
        ],
        help="Filter vulnerabilities by severity",
    )

    return parser.parse_args()


def main():

    args = parse_args()

    service = ThreatService()

    vulnerabilities = service.get_latest_vulnerabilities(
        severity=args.severity,
    )

    show_vulnerabilities(vulnerabilities)


if __name__ == "__main__":
    main()