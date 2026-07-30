from datetime import UTC, datetime
from time import perf_counter

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

        start_time = perf_counter()

        try:
            last_sync = self.repository.get_metadata("last_sync")

            if last_sync:
                logger.info("Incremental sync since %s", last_sync)
            else:
                logger.info("No previous sync found. Performing full sync.")

            vulnerabilities = self.nvd.fetch_latest(last_sync)

            logger.info("Retrieved %d CVEs from NVD", len(vulnerabilities))

            stats = {
                "new": 0,
                "updated": 0,
                "skipped": 0,
            }

            for cve in vulnerabilities:
                result = self.repository.upsert(cve)
                stats[result] += 1

            self.repository.set_metadata(
                "last_sync",
                datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            )

            duration = perf_counter() - start_time
            total = self.repository.count_cves()

            logger.info("Synchronization completed")

            logger.info("-" * 40)
            logger.info("Synchronization Summary")
            logger.info("-" * 40)
            logger.info("Retrieved      : %d", len(vulnerabilities))
            logger.info("New CVEs       : %d", stats["new"])
            logger.info("Updated CVEs   : %d", stats["updated"])
            logger.info("Skipped CVEs   : %d", stats["skipped"])
            logger.info("Database Total : %d", total)
            logger.info("Duration       : %.2f seconds", duration)
            logger.info("-" * 40)

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
