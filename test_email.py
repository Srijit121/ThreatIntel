from app.services.threat_service import ThreatService

service = ThreatService()

stats = {
    "new": 5,
    "updated": 2,
    "skipped": 8,
}

report = service.export_report()

service.send_report(
    report_path=report,
    stats=stats,
    duration=2.34,
)

print("✅ Test email sent successfully.")
