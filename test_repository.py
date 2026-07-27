from app.models.cve import CVE
from app.repositories.cve_repository import CVERepository

repo = CVERepository()

repo.save(
    CVE(
        id="CVE-TEST-0001",
        published="2026-07-28",
        severity="HIGH",
        description="This is a repository test."
    )
)

for cve in repo.get_all():
    print(cve)