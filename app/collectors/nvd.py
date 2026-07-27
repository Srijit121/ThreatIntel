import requests
from datetime import datetime, timedelta, UTC

from app.models.cve import CVE


class NVDCollector:
    """Collects vulnerability data from the NVD API."""

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def fetch_latest(self, results_per_page=5):
        """Fetch the latest CVEs published in the last 24 hours."""

        now = datetime.now(UTC)
        yesterday = now - timedelta(days=1)

        response = requests.get(
            self.BASE_URL,
            params={
                "resultsPerPage": results_per_page,
                "pubStartDate": yesterday.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                "pubEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            },
            timeout=30,
        )

        response.raise_for_status()

        data = response.json()

        vulnerabilities = []

        for item in data.get("vulnerabilities", []):
            cve = item["cve"]

            # Get English description
            description = ""

            for desc in cve.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            # Determine severity
            severity = "UNKNOWN"
            metrics = cve.get("metrics", {})

            if "cvssMetricV31" in metrics:
                severity = metrics["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
            elif "cvssMetricV30" in metrics:
                severity = metrics["cvssMetricV30"][0]["cvssData"]["baseSeverity"]
            elif "cvssMetricV2" in metrics:
                severity = metrics["cvssMetricV2"][0]["baseSeverity"]

            vulnerabilities.append(
                CVE(
                    id=cve["id"],
                    description=description,
                    published=cve["published"],
                    severity=severity,
                )
            )

        return vulnerabilities