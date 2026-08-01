from app.repositories.cve_repository import CVERepository
from app.services.threat_service import ThreatService

repo = CVERepository()
service = ThreatService()

cve = repo.get_by_id("CVE-2024-21338")

if cve:
    service._notify_kev(cve)
    print("✅ KEV notification sent")
else:
    print("❌ CVE not found")
