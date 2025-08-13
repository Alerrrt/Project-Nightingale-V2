import os
import csv
from datetime import datetime
from typing import Optional

_SHEETS_READY = False
_SHEET = None

def _init_sheets():
    global _SHEETS_READY, _SHEET
    if _SHEETS_READY:
        return
    try:
        enabled = os.getenv("GOOGLE_SHEETS_ENABLED", "false").lower() == "true"
        if not enabled:
            _SHEETS_READY = True
            return
        # Prefer JSON base64 env, otherwise file path
        import json
        import base64
        import gspread
        from google.oauth2.service_account import Credentials

        raw = os.getenv("GOOGLE_SERVICE_ACCOUNT_JSON_B64")
        path = os.getenv("GOOGLE_SERVICE_ACCOUNT_FILE")

        if raw:
            info = json.loads(base64.b64decode(raw).decode("utf-8"))
        elif path and os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                info = json.load(f)
        else:
            _SHEETS_READY = True
            return

        scopes = [
            "https://www.googleapis.com/auth/spreadsheets",
            "https://www.googleapis.com/auth/drive.file",
        ]
        creds = Credentials.from_service_account_info(info, scopes=scopes)
        client = gspread.authorize(creds)
        sheet_id = os.getenv("GOOGLE_SHEET_ID")
        sheet_name = os.getenv("GOOGLE_SHEET_NAME", "Newsletter")
        if not sheet_id:
            _SHEETS_READY = True
            return
        sh = client.open_by_key(sheet_id)
        try:
            _SHEET = sh.worksheet(sheet_name)
        except Exception:
            _SHEET = sh.add_worksheet(title=sheet_name, rows=1000, cols=5)
            _SHEET.append_row(["timestamp", "email"])  # header
        _SHEETS_READY = True
    except Exception:
        _SHEETS_READY = True
        _SHEET = None


def store_email(email: str) -> None:
    """Append email to Google Sheets if configured, else fallback to CSV file."""
    _init_sheets()
    ts = datetime.utcnow().isoformat()

    if _SHEET is not None:
        try:
            _SHEET.append_row([ts, email])
            return
        except Exception:
            pass

    # CSV fallback (local)
    target = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs", "newsletter.csv")
    os.makedirs(os.path.dirname(target), exist_ok=True)
    new_file = not os.path.exists(target)
    with open(target, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if new_file:
            writer.writerow(["timestamp", "email"])  # header
        writer.writerow([ts, email])

