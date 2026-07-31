from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = BASE_DIR / "instance" / "staffhub.db"

# Development-only secret key for the starter app.
# Students should not use this value in a real production system.
SECRET_KEY = "staffhub-starter-development-key"
