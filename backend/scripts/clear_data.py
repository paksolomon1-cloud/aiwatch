from __future__ import annotations

import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from app.storage import clear_db


def main() -> int:
    clear_db()
    print("Cleared AIWatch local database.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
