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
                    cve_id, published, modified, severity, cvss_score,
                    cwe, vendor, product, reference_urls, description
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
        """Return the total number of CVEs stored in the database."""

        conn = self.database.connect()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT COUNT(*)
            FROM vulnerabilities
            """)

        total = cursor.fetchone()[0]

        conn.close()

        return total

    def count_kev(self):
        """Return the total number of Known Exploited Vulnerabilities."""

        conn = self.database.connect()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT COUNT(*)
            FROM vulnerabilities
            WHERE kev = 1
            """)

        total = cursor.fetchone()[0]

        conn.close()

        return total

    def get_all(self, limit=25):
        """Return the most actionable vulnerabilities."""
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
                description,
                kev,
                kev_date,
                kev_due_date
            FROM vulnerabilities
            WHERE
                vendor IS NOT NULL
                AND vendor != 'n/a'
                AND cvss_score IS NOT NULL
            ORDER BY
                kev DESC,

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
                kev=bool(row[10]),
                kev_date=row[11],
                kev_due_date=row[12],
            )
            for row in rows
        ]

    def get_all_cves(self):
        """Return every CVE stored in the database."""
        conn = self.database.connect()
        cursor = conn.cursor()

        cursor.execute("""
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
                description,
                kev,
                kev_date,
                kev_due_date
            FROM vulnerabilities
            ORDER BY datetime(published) DESC
            """)

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
                kev=bool(row[10]),
                kev_date=row[11],
                kev_due_date=row[12],
            )
            for row in rows
        ]

    def get_by_id(self, cve_id: str):
        """Return a single CVE by ID."""

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
                description,
                kev,
                kev_date,
                kev_due_date
            FROM vulnerabilities
            WHERE cve_id = ?
            """,
            (cve_id,),
        )

        row = cursor.fetchone()

        conn.close()

        if row is None:
            return None

        return CVE(
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
            kev=bool(row[10]),
            kev_date=row[11],
            kev_due_date=row[12],
        )

    def get_statistics(self):
        """Return database statistics."""

        conn = self.database.connect()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT severity, COUNT(*)
            FROM vulnerabilities
            GROUP BY severity
            """)

        severity = {}

        for row in cursor.fetchall():
            severity[row[0] or "UNKNOWN"] = row[1]

        stats = {
            "total": self.count_cves(),
            "kev": self.count_kev(),
            "severity": severity,
        }

        conn.close()

        return stats

    def mark_as_kev(
        self,
        cve_id: str,
        date_added: str,
        due_date: str,
    ):
        """
        Mark a CVE as KEV.

        Returns:
            True  -> Newly added to KEV
            False -> Already marked as KEV or CVE not found
        """

        conn = self.database.connect()
        cursor = conn.cursor()

        # Check current KEV state
        cursor.execute(
            """
            SELECT kev
            FROM vulnerabilities
            WHERE cve_id = ?
            """,
            (cve_id,),
        )

        row = cursor.fetchone()

        if row is None:
            conn.close()
            return False

        # Already KEV
        if row[0] == 1:
            conn.close()
            return False

        # First time becoming KEV
        cursor.execute(
            """
            UPDATE vulnerabilities
            SET
                kev = 1,
                kev_date = ?,
                kev_due_date = ?
            WHERE cve_id = ?
            """,
            (
                date_added,
                due_date,
                cve_id,
            ),
        )

        conn.commit()
        conn.close()

        return True

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
