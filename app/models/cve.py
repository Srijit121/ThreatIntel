from dataclasses import dataclass


@dataclass(slots=True)
class CVE:
    id: str
    description: str
    published: str
    severity: str
