import sqlite3
from pathlib import Path


class Database:
    """Handles the SQLite database connection."""

    def __init__(self):
        # Create the data directory if it doesn't exist
        data_dir = Path("data")
        data_dir.mkdir(exist_ok=True)

        self.db_path = data_dir / "threatintel.db"

    def connect(self):
        """Return a SQLite database connection."""
        return sqlite3.connect(self.db_path)

    def initialize(self):
        """Create the required database tables."""

        conn = self.connect()
        cursor = conn.cursor()

        # Store vulnerability records
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                cve_id TEXT PRIMARY KEY,
                published TEXT NOT NULL,
                severity TEXT,
                description TEXT NOT NULL
            )
            """
        )

        # Store application metadata
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT
            )
            """
        )

        conn.commit()
        conn.close()