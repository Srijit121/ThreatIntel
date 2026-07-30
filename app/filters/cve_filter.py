from app.models.cve import CVE


class CVEFilter:
    """Filters vulnerability collections."""

    @staticmethod
    def by_severity(vulnerabilities: list[CVE], severity: str) -> list[CVE]:
        severity = severity.upper()

        return [cve for cve in vulnerabilities if cve.severity.upper() == severity]
