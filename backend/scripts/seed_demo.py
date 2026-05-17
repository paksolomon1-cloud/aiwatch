from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request

BASE_URL = "http://127.0.0.1:7330"
HEALTH_URL = f"{BASE_URL}/v1/health"
BACKEND_DOWN_MESSAGE = (
    "AIWatch backend is not running. Start it with: "
    "py -3.12 -m uvicorn app.main:app --reload --port 7330"
)
DEV_ENDPOINTS_DISABLED_MESSAGE = (
    "AIWatch dev endpoints are disabled. Start the backend with "
    "AIWATCH_DEV_MODE=true for local demos."
)

def _backend_running() -> bool:
    try:
        with urllib.request.urlopen(HEALTH_URL, timeout=2) as response:
            return response.status == 200
    except urllib.error.URLError:
        return False


def _seed_demo(*, extended: bool = False) -> dict[str, object]:
    body = json.dumps({}).encode("utf-8")
    request = urllib.request.Request(
        f"{BASE_URL}/v1/dev/seed-demo?clear=true&extended={'true' if extended else 'false'}",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


def _format_result(item: dict[str, object]) -> str:
    name = str(item.get("name", "unknown"))
    event_id = str(item.get("event_id", "unknown"))
    alerts_created = int(item.get("alerts_created", 0))
    rule_ids = ", ".join(str(rule_id) for rule_id in item.get("rule_ids", []))
    alert_label = "alert" if alerts_created == 1 else "alerts"
    suffix = f" -> {rule_ids}" if rule_ids else " -> none"
    return f"[ok] {name}: event_id={event_id}, {alerts_created} {alert_label}{suffix}"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--extended", action="store_true", help="Seed the MCP registry demo events.")
    args = parser.parse_args()

    if not _backend_running():
        print(BACKEND_DOWN_MESSAGE)
        return 1

    try:
        response_data = _seed_demo(extended=args.extended)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            print(DEV_ENDPOINTS_DISABLED_MESSAGE)
            return 1
        raise
    for item in response_data.get("items", []):
        if isinstance(item, dict):
            print(_format_result(item))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
