from datetime import datetime, UTC

from app.collectors.nvd import NVDCollector
from app.filters.cve_filter import CVEFilter
from app.logging.logger import logger
from app.repositories.cve_repository import CVERepository


class ThreatService:
    """Service layer for threat intelligence operations."""

    def __init__(self):
        self.nvd = NVDCollector()
        self.repository = CVERepository()

    def sync(self):
        """Synchronize vulnerabilities from NVD."""

        logger.info("Synchronization started")

        try:
            last_sync = self.repository.get_metadata("last_sync")

            if last_sync:
                logger.info("Incremental sync since %s", last_sync)
            else:
                logger.info("No previous sync found. Performing full sync.")

            vulnerabilities = self.nvd.fetch_latest(last_sync)

            logger.info("Retrieved %d CVEs from NVD", len(vulnerabilities))

            for cve in vulnerabilities:
                self.repository.save(cve)

            self.repository.set_metadata(
                "last_sync",
                datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            )

            logger.info("Synchronization completed")

        except Exception:
            logger.exception("Synchronization failed")
            raise

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

        stats = self.repository.get_statistics()
        stats["last_sync"] = self.repository.get_metadata("last_sync")

        return stats