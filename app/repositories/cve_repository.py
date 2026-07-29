from app.database.database import Database
from app.models.cve import CVE


class CVERepository:
    """Repository for storing and retrieving CVEs."""

    def __init__(self):
        self.database = Database()
        self.database.initialize()

    def save(self, cve: CVE):
        """Save a CVE into SQLite."""

        conn = self.database.connect()
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT OR IGNORE INTO vulnerabilities
            (cve_id, published, severity, description)
            VALUES (?, ?, ?, ?)
            """,
            (
                cve.id,
                cve.published,
                cve.severity,
                cve.description,
            ),
        )

        conn.commit()
        conn.close()

    def get_all(self):
        """Return all stored CVEs."""

        conn = self.database.connect()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT cve_id,
                   published,
                   severity,
                   description
            FROM vulnerabilities
            ORDER BY published DESC
            """)

        rows = cursor.fetchall()

        conn.close()

        return [
            CVE(
                id=row[0],
                published=row[1],
                severity=row[2],
                description=row[3],
            )
            for row in rows
        ]

    def get_statistics(self):
        """Return vulnerability statistics."""

        conn = self.database.connect()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT COUNT(*)
            FROM vulnerabilities
            """)
        total = cursor.fetchone()[0]

        cursor.execute("""
            SELECT severity, COUNT(*)
            FROM vulnerabilities
            GROUP BY severity
            """)

        severity_counts = {severity: count for severity, count in cursor.fetchall()}

        conn.close()

        return {
            "total": total,
            "severity": severity_counts,
        }
    def set_metadata(self, key: str, value: str):
        """Store application metadata."""

        conn = self.database.connect()
        cursor = conn.cursor()

        cursor.execute(
        """
        INSERT INTO metadata (key, value)
        VALUES (?, ?)
        ON CONFLICT(key)
        DO UPDATE SET value = excluded.value
        """,
        (key, value),
        )

        conn.commit()
        conn.close()

    def get_metadata(self, key: str):
        """Retrieve application metadata."""

        conn = self.database.connect()
        cursor = conn.cursor()

        cursor.execute(
        """
        SELECT value
        FROM metadata
        WHERE key = ?
        """,
        (key,),
    )

        row = cursor.fetchone()

        conn.close()

        return row[0] if row else None    