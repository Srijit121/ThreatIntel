from app.repositories.cve_repository import CVERepository

repo = CVERepository()

for cve in repo.get_all_cves():
    if cve.kev:
        print(cve)
        print("KEV:", cve.kev)
        print("Added:", cve.kev_date)
        print("Due:", cve.kev_due_date)
        break
