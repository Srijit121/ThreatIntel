from app.collectors.nvd import NVDCollector
from app.filters.cve_filter import CVEFilter
from app.repositories.cve_repository import CVERepository
from app.logging.logger import logger


class ThreatService:
    def __init__(self):
        self.nvd = NVDCollector()
        self.repository = CVERepository()

    def sync(self):
        """Synchronize vulnerabilities from NVD."""

        logger.info("Synchronization started")

        vulnerabilities = self.nvd.fetch_latest()

        logger.info("Retrieved %d CVEs from NVD", len(vulnerabilities))

        for cve in vulnerabilities:
            self.repository.save(cve)

        logger.info("Synchronization completed")

    def get_vulnerabilities(self, severity=None):
        """Return vulnerabilities stored in SQLite."""

        vulnerabilities = self.repository.get_all()

        if severity:
            vulnerabilities = CVEFilter.by_severity(
                vulnerabilities,
                severity,
            )

        return vulnerabilities

    def status(self):
        """Return database statistics."""

        return self.repository.get_statistics()