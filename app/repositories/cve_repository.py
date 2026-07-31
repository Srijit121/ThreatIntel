from app.database.database import Database
from app.models.cve import CVE


class CVERepository:
    """Repository for storing and retrieving CVEs."""

    def __init__(self):
        self.database = Database()
        self.database.initialize()

    def upsert(self, cve: CVE):
        """
        Insert a new CVE, update an existing one if it has changed,
        or skip it if nothing has changed.

        Returns:
            "new", "updated", or "skipped"
        """

        conn = self.database.connect()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT
                published,
                modified,
                severity,
                cvss_score,
                cwe,
                vendor,
                product,
                reference_urls,
                description
            FROM vulnerabilities
            WHERE cve_id = ?
            """,
            (cve.id,),
        )

        existing = cursor.fetchone()

        if existing is None:
            cursor.execute(
                """
                INSERT INTO vulnerabilities (
                    cve_id,
                    published,
                    modified,
                    severity,
                    cvss_score,
                    cwe,
                    vendor,
                    product,
                    reference_urls,
                    description
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    cve.id,
                    cve.published,
                    cve.modified,
                    cve.severity,
                    cve.cvss_score,
                    cve.cwe,
                    cve.vendor,
                    cve.product,
                    cve.reference_urls,
                    cve.description,
                ),
            )

            conn.commit()
            conn.close()
            return "new"

        if existing != (
            cve.published,
            cve.modified,
            cve.severity,
            cve.cvss_score,
            cve.cwe,
            cve.vendor,
            cve.product,
            cve.reference_urls,
            cve.description,
        ):
            cursor.execute(
                """
                UPDATE vulnerabilities
                SET
                    published = ?,
                    modified = ?,
                    severity = ?,
                    cvss_score = ?,
                    cwe = ?,
                    vendor = ?,
                    product = ?,
                    reference_urls = ?,
                    description = ?
                WHERE cve_id = ?
                """,
                (
                    cve.published,
                    cve.modified,
                    cve.severity,
                    cve.cvss_score,
                    cve.cwe,
                    cve.vendor,
                    cve.product,
                    cve.reference_urls,
                    cve.description,
                    cve.id,
                ),
            )

            conn.commit()
            conn.close()
            return "updated"

        conn.close()
        return "skipped"

    def count_cves(self):
        """Return the total number of stored CVEs."""

        conn = self.database.connect()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT COUNT(*)
            FROM vulnerabilities
            """)

        total = cursor.fetchone()[0]

        conn.close()

        return total

    def get_all(self, limit=25):
        """
         Return the most actionable vulnerabilities.

        Priority:
        1. Critical
        2. High
        3. Medium
        4. Low
        5. Unknown

        Within each severity, sort by highest CVSS score first,
        then by newest published date.

        Only display vulnerabilities that have vendor and CVSS data.
        """

        conn = self.database.connect()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT
                cve_id,
                published,
                modified,
                severity,
                cvss_score,
                cwe,
                vendor,
                product,
                reference_urls,
                description
            FROM vulnerabilities
            WHERE
                vendor IS NOT NULL
                AND vendor != 'n/a'
                AND cvss_score IS NOT NULL
            ORDER BY
                CASE severity
                    WHEN 'CRITICAL' THEN 1
                    WHEN 'HIGH' THEN 2
                    WHEN 'MEDIUM' THEN 3
                    WHEN 'LOW' THEN 4
                    ELSE 5
                END,
                cvss_score DESC,
                datetime(published) DESC
            LIMIT ?
            """,
            (limit,),
        )

        rows = cursor.fetchall()

        conn.close()

        return [
            CVE(
                id=row[0],
                published=row[1],
                modified=row[2],
                severity=row[3],
                cvss_score=row[4],
                cwe=row[5],
                vendor=row[6],
                product=row[7],
                reference_urls=row[8],
                description=row[9],
            )
            for row in rows
        ]

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
