from app.collectors.nvd import NVDCollector
from app.filters.cve_filter import CVEFilter


class ThreatService:

    def __init__(self):
        self.nvd = NVDCollector()

    def get_latest_vulnerabilities(self, severity=None):

        vulnerabilities = self.nvd.fetch_latest()

        if severity:
            vulnerabilities = CVEFilter.by_severity(
                vulnerabilities,
                severity,
            )

        return vulnerabilities