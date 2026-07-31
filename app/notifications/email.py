import mimetypes
import os
import smtplib
from email.message import EmailMessage
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


class EmailNotifier:
    """Send email notifications using Gmail SMTP."""

    def __init__(self):
        self.smtp_server = os.getenv("SMTP_SERVER")
        self.smtp_port = int(os.getenv("SMTP_PORT"))
        self.username = os.getenv("SMTP_USERNAME")
        self.password = os.getenv("SMTP_PASSWORD")
        self.recipient = os.getenv("EMAIL_TO")

    def send(
        self,
        subject: str,
        body: str,
        attachment: str | None = None,
    ):
        """Send an email with an optional attachment."""

        message = EmailMessage()

        message["Subject"] = subject
        message["From"] = self.username
        message["To"] = self.recipient

        message.set_content(body)

        if attachment:

            file_path = Path(attachment)

            if not file_path.exists():
                raise FileNotFoundError(f"Attachment not found: {file_path}")

            mime_type, _ = mimetypes.guess_type(file_path)

            if mime_type is None:
                mime_type = "application/octet-stream"

            maintype, subtype = mime_type.split("/", 1)

            with file_path.open("rb") as file:
                message.add_attachment(
                    file.read(),
                    maintype=maintype,
                    subtype=subtype,
                    filename=file_path.name,
                )

        with smtplib.SMTP(
            self.smtp_server,
            self.smtp_port,
        ) as smtp:

            smtp.starttls()

            smtp.login(
                self.username,
                self.password,
            )

            smtp.send_message(message)
