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
CRON_SECRET = os.environ.get("CRON_SECRET")

PH_TZ = timezone(timedelta(hours=8))
OFFICIAL_START_HOUR = 8
OFFICIAL_START_MINUTE = 0
GRACE_MINUTES = 0   # set to 10 if you want grace

def as_aware_utc(dt):
    """Ensure datetime is timezone-aware in UTC."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)

def compute_late(ph_dt: datetime):
    """Returns (is_late: bool, late_minutes: int)."""
    start = datetime(
        ph_dt.year, ph_dt.month, ph_dt.day,
        OFFICIAL_START_HOUR, OFFICIAL_START_MINUTE,
        tzinfo=PH_TZ
    ) + timedelta(minutes=GRACE_MINUTES)

    if ph_dt <= start:
        return False, 0

    late_mins = int((ph_dt - start).total_seconds() // 60)
    return True, late_mins

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
    # CRON SECRET
    # =========================================================


@app.route("/cron/remind-missing-timeout", methods=["GET"])
def cron_remind_missing_timeout():

    secret = request.args.get("secret", "")
    if not CRON_SECRET or secret != CRON_SECRET:
        return "unauthorized", 401

    today_ph = datetime.now(PH_TZ).date()

    conn = get_db_connection()
    try:
        with conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                # Find students who timed in today but no time out yet
                cur.execute("""
                    SELECT u.id AS user_id, u.messenger_id, u.full_name
                    FROM dtr_records r
                    JOIN users u ON u.id = r.user_id
                    WHERE r.date = %s
                      AND r.time_in IS NOT NULL
                      AND r.time_out IS NULL
                """, (today_ph,))
                rows = cur.fetchall()

                sent = 0
                for row in rows:
                    # Insert reminder log (skip if already reminded)
                    cur.execute("""
                        INSERT INTO reminder_logs (user_id, date, reminder_type)
                        VALUES (%s, %s, %s)
                        ON CONFLICT DO NOTHING
                    """, (row["user_id"], today_ph, "missing_time_out_6pm"))

                    if cur.rowcount == 0:
                        continue  # already reminded today

                    name = row.get("full_name") or ""
                    msg = (
                        f"⏰ Reminder{name and f', {name}'}: You still have no TIME OUT recorded for today.\n"
                        f"Reply: TIME OUT"
                    )
                    send_message(row["messenger_id"], msg)
                    sent += 1

        return {"date": str(today_ph), "targets": len(rows), "sent": sent}, 200

    except Exception as e:
        print("cron reminder error:", e)
        return "error", 500
    finally:
        conn.close()

# =========================================================
# Core handlers (minimal)
# =========================================================

def handle_time_punch(cur, sender_id: str, cmd: str, utc_dt: datetime, today_ph: date) -> str:
    # Load user
    cur.execute("""
        SELECT id, start_date, end_date
          FROM users
        WHERE messenger_id = %s
    """, (sender_id,))
    user = cur.fetchone()
    if not user:
        return "⚠️ Please REGISTER first."

    user_id = user["id"]
    start_date = user["start_date"]  # DATE in DB
    end_date = user["end_date"]      # DATE in DB

    # OJT period enforcement (based on PH local date)
    if start_date is not None and today_ph < start_date:
        return f"⛔ OJT not started yet. Start date: {start_date}"
    if end_date is not None and today_ph > end_date:
        return f"⛔ OJT already ended. End date: {end_date}"

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

        # Check for previous open session (before today)
        cur.execute("""
            SELECT date
            FROM dtr_records
            WHERE user_id = %s
              AND time_in IS NOT NULL
              AND time_out IS NULL
              AND date < %s
            ORDER BY date DESC
            LIMIT 1
        """, (user_id, today_ph))

        open_session = cur.fetchone()

        if open_session:
            return f"⚠️ You have an open session from {open_session['date']}. Please contact your coordinator."

        # --- compute late ---
        ph_now = utc_dt.astimezone(PH_TZ)
        is_late, late_minutes = compute_late(ph_now)

        if not record:
            cur.execute("""
                INSERT INTO dtr_records (user_id, date, time_in, is_late, late_minutes)
                VALUES (%s, %s, %s, %s, %s)
            """, (user_id, today_ph, utc_dt, is_late, late_minutes))
        else:
            cur.execute("""
                UPDATE dtr_records
                SET time_in = %s,
                    is_late = %s,
                    late_minutes = %s
                WHERE id = %s
            """, (utc_dt, is_late, late_minutes, record["id"]))

        t = ph_now.strftime('%I:%M %p')
        if is_late:
            return f"✅ TIME IN recorded at {t} (Late {late_minutes} min)"
        return f"✅ TIME IN recorded at {t}"

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
        SELECT time_in, time_out, minutes_worked, is_late, late_minutes
        FROM dtr_records
        WHERE user_id = %s AND date = %s
    """, (user_id, today_ph))
    today_rec = cur.fetchone() or {}

    late_note = ""
    if today_rec.get("is_late"):
        late_note = f" (Late {today_rec.get('late_minutes', 0)} min)"

    # Totals
    cur.execute("""
        SELECT COALESCE(SUM(COALESCE(minutes_worked, 0)), 0) AS total_minutes
        FROM dtr_records
        WHERE user_id = %s
    """, (user_id,))
    total_minutes = int(cur.fetchone()["total_minutes"])

    cur.execute("""
        SELECT COUNT(*) AS late_count
        FROM dtr_records
        WHERE user_id = %s
          AND is_late = TRUE
    """, (user_id,))
    late_count = int(cur.fetchone()["late_count"])

    # Missing TIME OUTs (before today)
    cur.execute("""
        SELECT
          COUNT(*) AS missing_count,
          MAX(date) AS latest_missing_date
        FROM dtr_records
        WHERE user_id = %s
          AND time_in IS NOT NULL
          AND time_out IS NULL
          AND date < %s
    """, (user_id, today_ph))
    missing = cur.fetchone()
    missing_count = int(missing["missing_count"])
    latest_missing_date = missing["latest_missing_date"]  # may be None

    required_minutes = required_hours * 60
    remaining_minutes = max(0, required_minutes - total_minutes)

    # Format
    time_in = today_rec.get("time_in")
    time_out = today_rec.get("time_out")
    minutes_today = today_rec.get("minutes_worked")

    today_worked = "—" if minutes_today is None else fmt_hm(int(minutes_today))

    latest_text = "—" if latest_missing_date is None else str(latest_missing_date)

    return (
        f"📌 STATUS\n"
        f"Today ({today_ph}):\n"
        f"• Time In: {fmt_ph(time_in)}{late_note}\n"
        f"• Time Out: {fmt_ph(time_out)}\n"
        f"• Worked today: {today_worked}\n\n"
        f"Totals:\n"
        f"• Accumulated: {fmt_hm(total_minutes)}\n"
        f"• Remaining: {fmt_hm(remaining_minutes)} (of {required_hours}h)\n\n"
        f"Compliance:\n"
        f"• Missing time-outs: {missing_count}\n"
        f"• Latest missing date: {latest_text}\n"
        f"• Late count: {late_count}"
    )
# =========================================================
# Home
# =========================================================

@app.route("/")
def home():
    return "OJT DTR Bot Running"









