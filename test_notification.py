from app.repositories.cve_repository import CVERepository
from app.services.threat_service import ThreatService

repo = CVERepository()
service = ThreatService()

# Get the highest priority CVE (currently a KEV)
cve = repo.get_all(limit=1)[0]

print(f"Testing notification for {cve.id}")

service._notify(cve)

print("✅ Notification sent")
