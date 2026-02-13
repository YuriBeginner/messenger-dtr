from flask import Flask, request
from datetime import datetime, timezone, timedelta, date
import os
import psycopg2
from psycopg2.extras import RealDictCursor
import requests
from datetime import timezone

app = Flask(__name__)

VERIFY_TOKEN = "ojt_dtr_token"
PAGE_ACCESS_TOKEN = os.environ.get("PAGE_ACCESS_TOKEN")
DATABASE_URL = os.environ.get("DATABASE_URL")

PH_TZ = timezone(timedelta(hours=8))

def as_aware_utc(dt):
    """Ensure datetime is timezone-aware in UTC."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)

# =========================================================
# Database
# =========================================================

def get_db_connection():
    return psycopg2.connect(DATABASE_URL)

# =========================================================
# Messenger
# =========================================================

def send_message(psid: str, message: str):
    url = f"https://graph.facebook.com/v19.0/me/messages?access_token={PAGE_ACCESS_TOKEN}"
    payload = {"recipient": {"id": psid}, "message": {"text": message}}
    try:
        r = requests.post(url, json=payload, timeout=10)
        if r.status_code >= 400:
            print("Messenger send error:", r.status_code, r.text)
    except Exception as e:
        print("Messenger request error:", e)

# =========================================================
# Time helpers
# =========================================================

def get_times_from_ms(ts_ms: int):
    """Returns (utc_dt, ph_dt, ph_date)."""
    utc_dt = datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc)
    ph_dt = utc_dt.astimezone(PH_TZ)
    return utc_dt, ph_dt, ph_dt.date()

def fmt_ph(dt):
    if not dt:
        return "—"
    dt = as_aware_utc(dt)
    ph = dt.astimezone(PH_TZ)
    return ph.strftime("%I:%M %p")

def fmt_hm(total_minutes: int):
    h = total_minutes // 60
    m = total_minutes % 60
    return f"{h}h {m}m"

# =========================================================
# Verify Webhook
# =========================================================

@app.route("/webhook", methods=["GET"])
def verify():
    token = request.args.get("hub.verify_token")
    challenge = request.args.get("hub.challenge")
    if token == VERIFY_TOKEN:
        return challenge
    return "Verification failed", 403

# =========================================================
# Webhook POST
# =========================================================

@app.route("/webhook", methods=["POST"])
def webhook():
    data = request.json

    try:
        entry = data["entry"][0]
        messaging = entry["messaging"][0]

        if "message" not in messaging or "text" not in messaging["message"]:
            return "ok", 200

        message_id = messaging["message"]["mid"]
        sender_id = messaging["sender"]["id"]
        print("PSID:", sender_id)
        raw_text = messaging["message"]["text"].strip()
        text = raw_text.upper()
        timestamp_ms = messaging["timestamp"]

        utc_dt, ph_dt, today_ph = get_times_from_ms(timestamp_ms)

        conn = get_db_connection()
        try:
            with conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    # ==========================
                    # Atomic dedup (CRITICAL)
                    # ==========================
                    cur.execute(
                        "INSERT INTO processed_messages (mid) VALUES (%s) ON CONFLICT DO NOTHING",
                        (message_id,)
                    )
                    if cur.rowcount == 0:
                        return "ok", 200  # duplicate delivery safely ignored

                    # ==========================
                    # Commands
                    # ==========================
                    if text == "STATUS":
                        msg = handle_status(cur, sender_id, today_ph)
                        send_message(sender_id, msg)
                        return "ok", 200

                    if text in ("TIME IN", "TIME OUT"):
                        msg = handle_time_punch(cur, sender_id, text, utc_dt, today_ph)
                        send_message(sender_id, msg)
                        return "ok", 200

                    if text == "HELP":
                        send_message(sender_id, "Commands: TIME IN, TIME OUT, STATUS")
                        return "ok", 200

                    # For now, ignore unknown
                    send_message(sender_id, "Type HELP for commands.")
                    return "ok", 200

        finally:
            conn.close()

    except Exception as e:
        print("Webhook error:", e)

    return "ok", 200

# =========================================================
# Core handlers (minimal)
# =========================================================

def handle_time_punch(cur, sender_id: str, cmd: str, utc_dt: datetime, today_ph: date) -> str:
    # Load user
    cur.execute("SELECT id FROM users WHERE messenger_id = %s", (sender_id,))
    user = cur.fetchone()
    if not user:
        return "⚠️ Please REGISTER first."

    user_id = user["id"]

    # Lock today's record row (if exists) to avoid races
    cur.execute("""
        SELECT id, time_in, time_out
        FROM dtr_records
        WHERE user_id = %s AND date = %s
        FOR UPDATE
    """, (user_id, today_ph))
    record = cur.fetchone()

    if cmd == "TIME IN":
        if record and record["time_in"] is not None:
            return "⚠️ TIME IN already recorded today."

        if not record:
            cur.execute("""
                INSERT INTO dtr_records (user_id, date, time_in)
                VALUES (%s, %s, %s)
            """, (user_id, today_ph, utc_dt))
        else:
            cur.execute("""
                UPDATE dtr_records
                SET time_in = %s
                WHERE id = %s
            """, (utc_dt, record["id"]))

        return f"✅ TIME IN recorded at {utc_dt.astimezone(PH_TZ).strftime('%I:%M %p')}"

    # TIME OUT
    if not record or record["time_in"] is None:
        return "⚠️ You must TIME IN first."

    if record["time_out"] is not None:
        return "⚠️ TIME OUT already recorded today."

    time_in_utc = as_aware_utc(record["time_in"])
    time_out_utc = as_aware_utc(utc_dt)

    if time_out_utc <= time_in_utc:
        return "⚠️ Invalid TIME OUT (earlier than TIME IN)."

    minutes_worked = int((time_out_utc - time_in_utc).total_seconds() // 60)

    cur.execute("""
        UPDATE dtr_records
        SET time_out = %s,
            minutes_worked = %s
        WHERE id = %s
    """, (time_out_utc, minutes_worked, record["id"]))

    return f"✅ TIME OUT recorded at {utc_dt.astimezone(PH_TZ).strftime('%I:%M %p')} (Worked {fmt_hm(minutes_worked)})"


def handle_status(cur, sender_id: str, today_ph: date) -> str:
    # Load user basics
    cur.execute("""
        SELECT id, required_hours
        FROM users
        WHERE messenger_id = %s
    """, (sender_id,))
    user = cur.fetchone()
    if not user:
        return "⚠️ Please REGISTER first."

    user_id = user["id"]
    required_hours = int(user["required_hours"] or 240)

    # Today record
    cur.execute("""
        SELECT time_in, time_out, minutes_worked
        FROM dtr_records
        WHERE user_id = %s AND date = %s
    """, (user_id, today_ph))
    today_rec = cur.fetchone() or {}

    # Totals
    cur.execute("""
        SELECT COALESCE(SUM(COALESCE(minutes_worked, 0)), 0) AS total_minutes
        FROM dtr_records
        WHERE user_id = %s
    """, (user_id,))
    total_minutes = int(cur.fetchone()["total_minutes"])

    required_minutes = required_hours * 60
    remaining_minutes = max(0, required_minutes - total_minutes)

    # Format
    time_in = today_rec.get("time_in")
    time_out = today_rec.get("time_out")
    minutes_today = today_rec.get("minutes_worked")

    today_worked = "—" if minutes_today is None else fmt_hm(int(minutes_today))

    return (
        f"📌 STATUS\n"
        f"Today ({today_ph}):\n"
        f"• Time In: {fmt_ph(time_in)}\n"
        f"• Time Out: {fmt_ph(time_out)}\n"
        f"• Worked today: {today_worked}\n\n"
        f"Totals:\n"
        f"• Accumulated: {fmt_hm(total_minutes)}\n"
        f"• Remaining: {fmt_hm(remaining_minutes)} (of {required_hours}h)"
    )

# =========================================================
# Home
# =========================================================

@app.route("/")
def home():
    return "OJT DTR Bot Running"


