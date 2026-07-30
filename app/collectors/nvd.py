from datetime import UTC, datetime, timedelta

import requests
from requests.adapters import HTTPAdapter
from requests.exceptions import (
    ConnectionError,
    HTTPError,
    ReadTimeout,
    Timeout,
)
from urllib3.util.retry import Retry

from app.models.cve import CVE


class NVDCollector:
    """Collects vulnerability data from the NVD API."""

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def _create_session(self):
        """Create an HTTP session with retry support."""

        retry = Retry(
            total=3,
            connect=3,
            read=3,
            status=3,
            backoff_factor=1,
            backoff_jitter=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=frozenset(["GET"]),
            raise_on_status=False,
        )

        session = requests.Session()

        session.mount(
            "https://",
            HTTPAdapter(max_retries=retry),
        )

        return session

    def fetch_latest(self, last_sync=None, results_per_page=25):
        """Fetch the latest CVEs from the NVD API."""

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

            params["pubStartDate"] = yesterday.strftime("%Y-%m-%dT%H:%M:%S.000Z")
            params["pubEndDate"] = now.strftime("%Y-%m-%dT%H:%M:%S.000Z")

        session = self._create_session()

        try:
            response = session.get(
                self.BASE_URL,
                params=params,
                timeout=30,
            )

            response.raise_for_status()

            data = response.json()

        except HTTPError as err:
            raise RuntimeError(
                f"NVD API returned HTTP {response.status_code}: {response.reason}"
            ) from err

        except (Timeout, ReadTimeout) as err:
            raise RuntimeError("Connection to the NVD API timed out.") from err

        except ConnectionError as err:
            raise RuntimeError("Unable to connect to the NVD API.") from err

        except ValueError as err:
            raise RuntimeError(
                "Received an invalid JSON response from the NVD API."
            ) from err

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
