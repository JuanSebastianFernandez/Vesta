"""
Minimal startup smoke check for CI.

Goal:
- Ensure FastAPI app can boot and serve basic endpoints.
- Avoid coupling smoke check to a real database connection.
"""

from pathlib import Path
import sys
from unittest.mock import patch

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import app.main as main_app


def run_smoke() -> None:
    with patch("app.main.create_db_and_tables", lambda: None):
        with TestClient(main_app.app) as client:
            root = client.get("/")
            health = client.get("/health/")

    if root.status_code != 200:
        raise SystemExit(f"Smoke failed: '/' returned {root.status_code}")
    if health.status_code != 200:
        raise SystemExit(f"Smoke failed: '/health/' returned {health.status_code}")


if __name__ == "__main__":
    run_smoke()
    print("Smoke startup check passed.")
