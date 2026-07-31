import json
from pathlib import Path


class WatchList:

    def __init__(self):
        config = Path("config/vendors.json")

        with config.open() as f:
            data = json.load(f)

        self.vendors = set(data["vendors"])
        self.products = set(data["products"])
        self.minimum_cvss = data["minimum_cvss"]
        self.notify_severity = set(data["notify_severity"])

    def should_notify(self, cve):

        vendor_match = cve.vendor is not None and cve.vendor in self.vendors

        product_match = cve.product is not None and cve.product in self.products

        severity_match = cve.severity in self.notify_severity

        score_match = cve.cvss_score is not None and cve.cvss_score >= self.minimum_cvss

        return (vendor_match or product_match) and (severity_match or score_match)
