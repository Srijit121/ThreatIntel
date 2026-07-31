import os
import smtplib
from email.message import EmailMessage

from dotenv import load_dotenv

load_dotenv()

SMTP_SERVER = os.getenv("SMTP_SERVER")
SMTP_PORT = int(os.getenv("SMTP_PORT"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
EMAIL_TO = os.getenv("EMAIL_TO")

msg = EmailMessage()
msg["Subject"] = "ThreatIntel Email Test"
msg["From"] = SMTP_USERNAME
msg["To"] = EMAIL_TO

msg.set_content("""Hello Srijit,

Congratulations!

Your ThreatIntel email integration is working successfully.

Next step:
✓ Send Excel reports automatically.

Regards,
ThreatIntel
""")

try:
    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as smtp:
        smtp.starttls()
        smtp.login(SMTP_USERNAME, SMTP_PASSWORD)
        smtp.send_message(msg)

    print("✅ Test email sent successfully!")

except Exception as e:
    print(f" Failed to send email: {e}")
