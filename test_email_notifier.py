from app.notifications.email import EmailNotifier

email = EmailNotifier()

email.send(
    subject="ThreatIntel Report",
    body=(
        "Hello Srijit,\n\n"
        "Please find today's ThreatIntel report attached.\n\n"
        "Regards,\n"
        "ThreatIntel"
    ),
    attachment="reports/CVE_Report.xlsx",
)

print("Email with attachment sent successfully.")
