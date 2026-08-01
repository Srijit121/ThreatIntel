from datetime import UTC, datetime
from time import perf_counter


from app.collectors.nvd import NVDCollector
from app.filters.cve_filter import CVEFilter
from app.logging.logger import logger
from app.models import cve
from app.notifications.ntfy import NtfyNotifier
from app.repositories.cve_repository import CVERepository
from app.watchlist import WatchList
from app.config import Settings
from app.notifications.email import EmailNotifier
from app.exporters.excel_exporter import ExcelExporter
from app.collectors.kev import KEVCollector


class ThreatService:
    """Service layer for threat intelligence operations."""

    def __init__(self):

        self.nvd = NVDCollector()
        self.kev = KEVCollector()
        self.repository = CVERepository()

        settings = Settings()
        self.watchlist = WatchList()
        self.notifier = NtfyNotifier(settings.ntfy_topic)

        self.email = EmailNotifier()
        self.exporter = ExcelExporter()

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

                notify = self.watchlist.should_notify(cve)

                print(
                    f"{cve.id} | Result={result} | Notify={notify} | "
                    f"Vendor={cve.vendor} | Product={cve.product} | "
                    f"Severity={cve.severity} | CVSS={cve.cvss_score}"
                )

                if result == "new" and notify:
                    try:
                        print(f"Sending notification for {cve.id}")
                        self._notify(cve)
                        logger.info("Notification sent for %s", cve.id)
                    except Exception:
                        logger.exception(
                            "Failed to send notification for %s",
                            cve.id,
                        )

            self.repository.set_metadata(
                "last_sync",
                datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            )

            # Synchronize CISA Known Exploited Vulnerabilities
            self.sync_kev()

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

            # -------------------------------------------------------
            # Generate and email report only when there are changes
            # -------------------------------------------------------
            if stats["new"] > 0 or stats["updated"] > 0:

                logger.info("Generating Excel report...")

                report = self.export_report()

                logger.info("Sending email report...")

                self.send_report(
                    report,
                    stats,
                    duration,
                )

        except Exception:
            logger.exception("Synchronization failed")
            raise

    def get_vulnerabilities(self, severity=None, limit=25):

        vulnerabilities = self.repository.get_all(limit)

        if severity:
            vulnerabilities = CVEFilter.by_severity(
                vulnerabilities,
                severity,
            )

        return vulnerabilities

    def status(self):

        stats = self.repository.get_statistics()
        stats["last_sync"] = self.repository.get_metadata("last_sync")

        return stats

    def export_report(self):
        """Generate an Excel report of all stored CVEs."""

        cves = self.repository.get_all_cves()

        report_path = self.exporter.export(
            cves,
            "reports/CVE_Report.xlsx",
        )

        logger.info("Excel report created: %s", report_path)

        return report_path

    def send_report(self, report_path, stats, duration):
        """Email the generated Excel report."""
        dashboard = self.repository.get_statistics()
        severity = dashboard["severity"]
        critical = severity.get("CRITICAL", 0)
        high = severity.get("HIGH", 0)
        medium = severity.get("MEDIUM", 0)
        low = severity.get("LOW", 0)
        unknown = severity.get("UNKNOWN", 0)

        subject = (
            f"ThreatIntel | "
            f"{stats['new']} New | "
            f"{stats['updated']} Updated | "
            f"{dashboard['kev']} KEV | "
            f"{datetime.now().strftime('%d-%b-%Y')}"
        )

        body = (
            "Hello Srijit,\n\n"
            "ThreatIntel synchronization completed successfully.\n\n"
            "==================================================\n"
            "Threat Intelligence Summary\n"
            "==================================================\n\n"
            "Synchronization\n"
            "--------------------------------------------------\n"
            f"Retrieved      : {stats['new'] + stats['updated'] + stats['skipped']}\n"
            f"New CVEs       : {stats['new']}\n"
            f"Updated CVEs   : {stats['updated']}\n"
            f"Skipped CVEs   : {stats['skipped']}\n\n"
            "Database\n"
            "--------------------------------------------------\n"
            f"Total CVEs     : {dashboard['total']}\n"
            f"KEV CVEs       : {dashboard['kev']}\n\n"
            "Severity Distribution\n"
            "--------------------------------------------------\n"
            f"Critical       : {critical}\n"
            f"High           : {high}\n"
            f"Medium         : {medium}\n"
            f"Low            : {low}\n"
            f"Unknown        : {unknown}\n\n"
            "Synchronization Details\n"
            "--------------------------------------------------\n"
            f"Completed      : {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
            f"Duration       : {duration:.2f} seconds\n\n"
            "The complete Excel report is attached.\n\n"
            "Regards,\n"
            "ThreatIntel"
        )

        self.email.send(
            subject=subject,
            body=body,
            attachment=report_path,
        )

        logger.info("Email report sent successfully.")

    def _notify(self, cve):
        """Send an ntfy notification."""

        if cve.kev:
            title = "KEV Alert"
            banner = "⚠️ Known Exploited Vulnerability (CISA KEV)"
            priority = "urgent"
        else:
            title = "ThreatIntel Alert"
            banner = "New Critical Vulnerability"
            priority = "high"

        message = (
            f"{banner}\n\n"
            f"CVE        : {cve.id}\n\n"
            f"Severity   : {cve.severity}\n"
            f"CVSS       : {cve.cvss_score}\n\n"
            f"Vendor     : {cve.vendor}\n"
            f"Product    : {cve.product}\n\n"
            f"Published  : {cve.published[:10]}\n\n"
            f"https://nvd.nist.gov/vuln/detail/{cve.id}"
        )

        self.notifier.send(
            title=title,
            message=message,
            priority=priority,
        )

    def _notify_kev(self, cve):
        """Notify when a CVE is newly added to the CISA KEV catalog."""

        reason = "Matched watchlist"

        if cve.vendor in self.watchlist.vendors:
            reason = f"Vendor matched ({cve.vendor})"

        elif cve.product in self.watchlist.products:
            reason = f"Product matched ({cve.product})"

        detected = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")

        separator = "────────────────────"

        patch_priority = "🔴 Immediate"
        if cve.severity == "HIGH":
            patch_priority = "🟠 High"

        elif cve.severity == "MEDIUM":
            patch_priority = "🟡 Medium"

        elif cve.severity == "LOW":
            patch_priority = "🟢 Low"

        parts = cve.id.split("-")
        year = parts[1] if len(parts) >= 3 else "Unknown"

        message = (
            "CISA Known Exploited Vulnerability\n"
            f"{separator}\n\n"
            "A watchlist vulnerability has been promoted to the\n"
            "CISA Known Exploited Vulnerabilities (KEV) Catalog.\n\n"
            f"Reason      : {reason}\n"
            f"Detected    : {detected}\n\n"
            f"{separator}\n\n"
            f"CVE         : {cve.id} ({year})\n\n"
            f"EPSS        : -\n"
            f"Vendor      : {cve.vendor}\n"
            f"Product     : {cve.product}\n\n"
            f"Severity    : {cve.severity}\n"
            f"CVSS        : {cve.cvss_score}\n\n"
            f"Exploitation: Confirmed (CISA KEV)\n"
            f"Patch Priority : {patch_priority}\n\n"
            f"KEV Added   : {cve.kev_date}\n"
            f"Due Date    : {cve.kev_due_date}\n\n"
            f"{separator}\n\n"
            "Recommended Action\n"
            "✔ Prioritize patching immediately.\n"
            "✔ Verify internet exposure.\n"
            "✔ Check for active exploitation.\n\n"
            f"https://nvd.nist.gov/vuln/detail/{cve.id}"
        )

        self.notifier.send(
            title="CISA KEV Alert",
            message=message,
            priority="urgent",
        )

    def sync_kev(self):
        """Synchronize the CISA KEV catalog."""

        logger.info("Synchronizing CISA KEV catalog...")

        kev_entries = self.kev.fetch()

        matched = 0

        for kev in kev_entries:

            new_kev = self.repository.mark_as_kev(
                kev.cve_id,
                kev.date_added,
                kev.due_date,
            )

            if new_kev:
                matched += 1
                cve = self.repository.get_by_id(kev.cve_id)

                if cve:
                    self._notify_kev(cve)

                    logger.info(
                        "KEV promotion notification sent for %s",
                        cve.id,
                    )

        logger.info(
            "KEV synchronization completed. Matched %d CVEs.",
            matched,
        )
