import requests


class NtfyNotifier:
    """Send notifications to an ntfy.sh topic."""

    def __init__(self, topic: str):
        self.url = f"https://ntfy.sh/{topic}"

    def send(self, title: str, message: str, priority: str = "high"):

        headers = {
            "Title": title,
            "Priority": priority,
            "Tags": "warning,shield",
        }

        response = requests.post(
            self.url,
            data=message.encode("utf-8"),
            headers=headers,
            timeout=10,
        )

        response.raise_for_status()
