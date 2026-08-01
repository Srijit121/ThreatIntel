from dataclasses import dataclass


@dataclass
class KEV:
    """Represents one CISA Known Exploited Vulnerability."""

    cve_id: str
    vendor: str
    product: str
    date_added: str
    due_date: str
