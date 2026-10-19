import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DB_PATH = os.getenv("DATABASE_PATH", str(BASE_DIR / "permissionguard.db"))
JWT_SECRET = os.getenv("JWT_SECRET", "permissionguard-secure-auth-secret-key-2026")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24

# Demo reference date for consistent time calculations (October 19, 2026)
REFERENCE_DATETIME = "2026-10-19T15:30:00"
