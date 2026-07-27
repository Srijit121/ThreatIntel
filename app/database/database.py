import sqlite3
from pathlib import Path


class Database:
    """Handles the SQLite database connection."""

    def __init__(self):
        data_dir = Path("data")
        data_dir.mkdir(exist_ok=True)

        self.db_path = data_dir / "threatintel.db"

    def connect(self):
        """Return a SQLite connection."""
        return sqlite3.connect(self.db_path)

    def initialize(self):
        """Create database tables if they do not exist."""

        conn = self.connect()
        cursor = conn.cursor()

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            cve_id TEXT PRIMARY KEY,
            published TEXT NOT NULL,
            severity TEXT,
            description TEXT NOT NULL
        )
        """)

        conn.commit()
        conn.close()