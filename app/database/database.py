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
        """Create and migrate the SQLite database."""

        conn = self.connect()
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                cve_id TEXT PRIMARY KEY,
                published TEXT NOT NULL,
                modified TEXT,
                severity TEXT,
                cvss_score REAL,
                cwe TEXT,
                vendor TEXT,
                product TEXT,
                reference_urls TEXT,
                description TEXT NOT NULL,
                kev INTEGER DEFAULT 0,
                kev_date TEXT,
                kev_due_date TEXT
            )
            """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT
            )
            """)

        # Migrate older databases by adding missing columns.
        cursor.execute("PRAGMA table_info(vulnerabilities)")
        existing_columns = {row[1] for row in cursor.fetchall()}

        migrations = {
            "modified": "TEXT",
            "cvss_score": "REAL",
            "cwe": "TEXT",
            "vendor": "TEXT",
            "product": "TEXT",
            "reference_urls": "TEXT",
            # KEV enrichment
            "kev": "INTEGER DEFAULT 0",
            "kev_date": "TEXT",
            "kev_due_date": "TEXT",
        }

        for column, datatype in migrations.items():
            if column not in existing_columns:
                cursor.execute(
                    f"ALTER TABLE vulnerabilities ADD COLUMN {column} {datatype}"
                )

        conn.commit()
        conn.close()
