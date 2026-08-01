from dataclasses import dataclass


@dataclass(slots=True)
class CVE:
    id: str
    description: str
    published: str
    modified: str | None = None
    severity: str | None = None
    cvss_score: float | None = None
    cwe: str | None = None
    vendor: str | None = None
    product: str | None = None
    reference_urls: str | None = None

    # CISA KEV Enrichment
    kev: bool = False
    kev_date: str | None = None
    kev_due_date: str | None = None
