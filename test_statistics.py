from app.repositories.cve_repository import CVERepository

repo = CVERepository()

stats = repo.get_statistics()

print(stats)
