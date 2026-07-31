import json
from pathlib import Path


class Settings:

    def __init__(self):

        with Path("config/settings.json").open() as f:
            self.data = json.load(f)

    @property
    def ntfy_enabled(self):
        return self.data["ntfy"]["enabled"]

    @property
    def ntfy_topic(self):
        return self.data["ntfy"]["topic"]
