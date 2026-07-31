from pathlib import Path
from openpyxl import Workbook
from openpyxl.styles import Font


class ExcelExporter:

    def export(self, cves, filename):
        wb = Workbook()
        ws = wb.active
        ws.title = "CVEs"

        headers = [
            "CVE ID",
            "Severity",
            "CVSS",
            "Published",
            "Description",
        ]

        for col, header in enumerate(headers, start=1):
            cell = ws.cell(row=1, column=col)
            cell.value = header
            cell.font = Font(bold=True)

        row = 2

        for cve in cves:
            ws.cell(row=row, column=1).value = cve.id
            ws.cell(row=row, column=2).value = cve.severity
            ws.cell(row=row, column=3).value = cve.cvss_score
            ws.cell(row=row, column=4).value = str(cve.published)
            ws.cell(row=row, column=5).value = cve.description

            row += 1

        Path(filename).parent.mkdir(parents=True, exist_ok=True)

        wb.save(filename)
