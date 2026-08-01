import requests

from app.models.kev import KEV


class KEVCollector:
    """Collect the CISA Known Exploited Vulnerabilities catalog."""

    URL = (
        "https://www.cisa.gov/sites/default/files/feeds/"
        "known_exploited_vulnerabilities.json"
    )

    def fetch(self):
        """Download and parse the KEV catalog."""

        response = requests.get(
            self.URL,
            timeout=30,
        )

        response.raise_for_status()

        data = response.json()

        vulnerabilities = []

        for item in data["vulnerabilities"]:

            vulnerabilities.append(
                KEV(
                    cve_id=item["cveID"],
                    vendor=item["vendorProject"],
                    product=item["product"],
                    date_added=item["dateAdded"],
                    due_date=item["dueDate"],
                )
            )

        return vulnerabilities
