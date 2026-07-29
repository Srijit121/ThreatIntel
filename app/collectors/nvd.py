import requests
from datetime import datetime, timedelta, UTC

from app.models.cve import CVE


class NVDCollector:
    """Collects vulnerability data from the NVD API."""

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def fetch_latest(self, last_sync=None, results_per_page=25):
        """Fetch the latest CVEs."""

        now = datetime.now(UTC)

        params = {
            "resultsPerPage": results_per_page,
        }

        if last_sync:
            # Convert legacy timestamps (without timezone) to NVD format
            if not last_sync.endswith("Z"):
                last_sync = (
                    datetime.fromisoformat(last_sync)
                    .replace(tzinfo=UTC)
                    .strftime("%Y-%m-%dT%H:%M:%S.000Z")
                )

            params["lastModStartDate"] = last_sync
            params["lastModEndDate"] = now.strftime("%Y-%m-%dT%H:%M:%S.000Z")

        else:
            yesterday = now - timedelta(days=1)

            params["pubStartDate"] = yesterday.strftime(
                "%Y-%m-%dT%H:%M:%S.000Z"
            )
            params["pubEndDate"] = now.strftime(
                "%Y-%m-%dT%H:%M:%S.000Z"
            )

        response = requests.get(
            self.BASE_URL,
            params=params,
            timeout=30,
        )

        response.raise_for_status()

        data = response.json()

        vulnerabilities = []

        for item in data.get("vulnerabilities", []):
            cve = item["cve"]

            description = ""

            for desc in cve.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

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