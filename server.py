from flask import Flask, request
from datetime import datetime, timezone, timedelta, date
import os
import psycopg2
from psycopg2.extras import RealDictCursor
import requests
import json

app = Flask(__name__)

VERIFY_TOKEN = "ojt_dtr_token"
PAGE_ACCESS_TOKEN = os.environ.get("PAGE_ACCESS_TOKEN")
DATABASE_URL = os.environ.get("DATABASE_URL")
CRON_SECRET = os.environ.get("CRON_SECRET")

PH_TZ = timezone(timedelta(hours=8))
OFFICIAL_START_HOUR = 8
OFFICIAL_START_MINUTE = 0
GRACE_MINUTES = 10  # grace period for lateness
REG_SESSION_EXPIRY_MINUTES = 15

# =========================================================
# Time + late helpers
# =========================================================

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
# Database
# =========================================================

def get_db_connection():
    return psycopg2.connect(DATABASE_URL)


def get_user_role(cur, sender_id: str):
    cur.execute("""
        SELECT role
        FROM users
        WHERE messenger_id = %s
    """, (sender_id,))
    row = cur.fetchone()
    if not row:
        return None
    return row.get("role", "student")

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
# Guided Registration (DB-backed state)
# =========================================================
def is_registered(cur, sender_id: str) -> bool:
    cur.execute("SELECT 1 FROM users WHERE messenger_id=%s", (sender_id,))
    return cur.fetchone() is not None

def reg_cleanup_expired(cur):
    cur.execute("""
        DELETE FROM registration_sessions
        WHERE updated_at < now() - (%s || ' minutes')::interval
    """, (REG_SESSION_EXPIRY_MINUTES,))

def reg_get_session(cur, messenger_id: str):
    cur.execute("""
        SELECT messenger_id, step, data, updated_at
        FROM registration_sessions
        WHERE messenger_id = %s
    """, (messenger_id,))
    sess = cur.fetchone()
    if not sess:
        return None

    # Expire after REG_SESSION_EXPIRY_MINUTES
    cur.execute("""
        SELECT (now() - %s::timestamptz) > (%s || ' minutes')::interval AS is_expired
    """, (sess["updated_at"], REG_SESSION_EXPIRY_MINUTES))
    expired = cur.fetchone()["is_expired"]

    if expired:
        reg_delete_session(cur, messenger_id)
        return None

    return sess

def reg_had_session(cur, messenger_id: str) -> bool:
    cur.execute("SELECT 1 FROM registration_sessions WHERE messenger_id=%s", (messenger_id,))
    return cur.fetchone() is not None

def reg_set_session(cur, messenger_id: str, step: str, data: dict):
    cur.execute("""
        INSERT INTO registration_sessions (messenger_id, step, data, updated_at)
        VALUES (%s, %s, %s::jsonb, now())
        ON CONFLICT (messenger_id)
        DO UPDATE SET step = EXCLUDED.step, data = EXCLUDED.data, updated_at = now()
    """, (messenger_id, step, json.dumps(data)))



def reg_delete_session(cur, messenger_id: str):
    cur.execute("DELETE FROM registration_sessions WHERE messenger_id = %s", (messenger_id,))

def start_registration(cur, sender_id: str) -> str:
    # If already registered, don’t start a new session
    cur.execute("SELECT id, full_name FROM users WHERE messenger_id = %s", (sender_id,))
    existing = cur.fetchone()
    if existing:
        name = existing.get("full_name") or "(no name)"
        return (
            f"⚠️ You are already registered as: {name}\n"
            f"If you need to update your details, contact your coordinator."
        )

    reg_set_session(cur, sender_id, "full_name", {})
    return (
        "📝 Registration started.\n\n"
        "What is your FULL NAME?\n"
        "(Type CANCEL anytime to stop.)"
    )

def handle_registration(cur, sender_id: str, raw_text: str) -> str:
    txt = raw_text.strip()

    # Global controls
    if txt.upper() == "CANCEL":
        reg_delete_session(cur, sender_id)
        return "✅ Registration cancelled."
    if txt.upper() == "RESTART":
        reg_delete_session(cur, sender_id)
        return start_registration(cur, sender_id)

    session = reg_get_session(cur, sender_id)
    if not session:
        return ""  # not in registration

    step = session["step"]
    data = session["data"] or {}

    def next_step(new_step: str, prompt: str):
        reg_set_session(cur, sender_id, new_step, data)
        return prompt

    if step == "full_name":
        if len(txt) < 3:
            return "Please enter your FULL NAME (at least 3 characters)."
        data["full_name"] = txt
        return next_step("student_id", "Enter your STUDENT ID:")

    if step == "student_id":
        if len(txt) < 2:
            return "Please enter your STUDENT ID."
        data["student_id"] = txt
        return next_step("course", "Enter your COURSE (example: BSIT):")

    if step == "course":
        data["course"] = txt.upper()
        return next_step("section", "Enter your SECTION (example: 4A):")

    if step == "section":
        data["section"] = txt.upper()
        return next_step("company_name", "Enter your COMPANY NAME:")

    if step == "company_name":
        data["company_name"] = txt
        return next_step("required_hours", "Enter REQUIRED HOURS (default 240). Type a number or reply SKIP:")

    if step == "required_hours":
        if txt.upper() == "SKIP":
            data["required_hours"] = 240
        else:
            try:
                rh = int(txt)
                if rh <= 0 or rh > 2000:
                    return "Required hours must be a valid number (example: 240). Try again or type SKIP."
                data["required_hours"] = rh
            except:
                return "Please enter a number for required hours (example: 240) or type SKIP."
        return next_step("start_date", "Enter START DATE (YYYY-MM-DD):")

    if step == "start_date":
        try:
            datetime.strptime(txt, "%Y-%m-%d")
            data["start_date"] = txt
        except:
            return "Invalid format. Enter START DATE as YYYY-MM-DD."
        return next_step("end_date", "Enter END DATE (YYYY-MM-DD):")

    if step == "end_date":
        try:
            datetime.strptime(txt, "%Y-%m-%d")
            data["end_date"] = txt
        except:
            return "Invalid format. Enter END DATE as YYYY-MM-DD."

        if data["end_date"] < data["start_date"]:
            return "⚠️ End date cannot be earlier than start date. Enter END DATE again (YYYY-MM-DD):"

        summary = (
            "✅ Please confirm your details:\n"
            f"Name: {data['full_name']}\n"
            f"Student ID: {data['student_id']}\n"
            f"Course: {data['course']}\n"
            f"Section: {data['section']}\n"
            f"Company: {data['company_name']}\n"
            f"Required Hours: {data['required_hours']}\n"
            f"Start: {data['start_date']}\n"
            f"End: {data['end_date']}\n\n"
            "Reply YES to confirm or NO to restart."
        )
        reg_set_session(cur, sender_id, "confirm", data)
        return summary

    if step == "confirm":
        if txt.upper() == "YES":
            cur.execute("""
                INSERT INTO users
                  (messenger_id, full_name, student_id, course, section, company_name, required_hours, start_date, end_date)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """, (
                sender_id,
                data["full_name"],
                data["student_id"],
                data["course"],
                data["section"],
                data["company_name"],
                int(data["required_hours"]),
                data["start_date"],
                data["end_date"]
            ))
            reg_delete_session(cur, sender_id)
            return "✅ Registration successful! Commands: TIME IN, TIME OUT, STATUS"

        if txt.upper() == "NO":
            reg_delete_session(cur, sender_id)
            return "Okay. Reply REGISTER to start again."

        return "Please reply YES to confirm or NO to restart."

    # Fallback: reset session if unknown step
    reg_delete_session(cur, sender_id)
    return "⚠️ Registration session reset. Reply REGISTER to start again."

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
                        return "ok", 200  # duplicate delivery ignored

                    reg_cleanup_expired(cur)

                    # ==========================
                    # Guided registration session takes priority
                    # ==========================
                    session = reg_get_session(cur, sender_id)
                    if session:
                        reply = handle_registration(cur, sender_id, raw_text)
                        if reply:
                            send_message(sender_id, reply)
                            return "ok", 200

                    # If user not registered, guide them (discoverability)
                    if not is_registered(cur, sender_id):
                        if text == "REGISTER":
                            send_message(sender_id, start_registration(cur, sender_id))
                            return "ok", 200

                        # If they are mid-registration, that was handled earlier.
                        send_message(
                            sender_id,
                            "👋 Welcome! This is the OJT Attendance Bot.\n\n"
                            "To get started, reply: REGISTER\n"
                            "After registration, you can use: TIME IN, TIME OUT, STATUS\n"
                            "Type HELP anytime."
                        )
                        return "ok", 200

                    # Start registration
                    if text == "REGISTER":
                        send_message(sender_id, start_registration(cur, sender_id))
                        return "ok", 200

                    # Allow cancel/restart even if session not found (user convenience)
                    if text in ("CANCEL", "RESTART"):
                        # if no session, just give guidance
                        send_message(sender_id, "No active registration. Reply REGISTER to start.")
                        return "ok", 200

                    # ==========================
                    # ADMIN COMMANDS
                    # ==========================
                    if text.startswith("ADMIN"):
                        role = get_user_role(cur, sender_id)
                        if role != "admin":
                            send_message(sender_id, "⛔ Admin access required.")
                            return "ok", 200

                        if text == "ADMIN MISSING TODAY":
                            msg = handle_admin_missing_today(cur, today_ph)
                            send_message(sender_id, msg)
                            return "ok", 200

                        send_message(sender_id, "Admin commands:\n• ADMIN MISSING TODAY")
                        return "ok", 200
                        

                    # ==========================
                    # STUDENT COMMANDS
                    # ==========================

                    if text not in ("REGISTER", "HELP", "TIME IN", "TIME OUT", "STATUS"):
                        send_message(sender_id, "If you were registering earlier, your session may have expired. Reply REGISTER to start again.")
                        return "ok", 200
    
                    if text == "STATUS":
                        msg = handle_status(cur, sender_id, today_ph)
                        send_message(sender_id, msg)
                        return "ok", 200

                    if text in ("TIME IN", "TIME OUT"):
                        msg = handle_time_punch(cur, sender_id, text, utc_dt, today_ph)
                        send_message(sender_id, msg)
                        return "ok", 200

                    if text == "HELP":
                        send_message(
                            sender_id,
                            "Commands:\n"
                            "• REGISTER (start)\n"
                            "• TIME IN\n"
                            "• TIME OUT\n"
                            "• STATUS\n"
                            "During registration:\n"
                            "• CANCEL\n"
                            "• RESTART"
                        )
                        return "ok", 200

                    send_message(sender_id, "Type HELP for commands.")
                    return "ok", 200

        finally:
            conn.close()

    except Exception as e:
        print("Webhook error:", e)

    return "ok", 200

# =========================================================
# Cron reminder (GET + secret query param)
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
                    cur.execute("""
                        INSERT INTO reminder_logs (user_id, date, reminder_type)
                        VALUES (%s, %s, %s)
                        ON CONFLICT DO NOTHING
                    """, (row["user_id"], today_ph, "missing_time_out_6pm"))

                    if cur.rowcount == 0:
                        continue

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
# Core handlers
# =========================================================

def handle_time_punch(cur, sender_id: str, cmd: str, utc_dt: datetime, today_ph: date) -> str:
    cur.execute("""
        SELECT id, start_date, end_date
        FROM users
        WHERE messenger_id = %s
    """, (sender_id,))
    user = cur.fetchone()
    if not user:
        return "⚠️ Please REGISTER first. Reply REGISTER to begin."

    user_id = user["id"]
    start_date = user["start_date"]
    end_date = user["end_date"]

    # OJT period enforcement
    if start_date is not None and today_ph < start_date:
        return f"⛔ OJT not started yet. Start date: {start_date}"
    if end_date is not None and today_ph > end_date:
        return f"⛔ OJT already ended. End date: {end_date}"

    # Lock today's record row (if exists)
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

        # Block if there is any previous open session
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

        t = ph_now.strftime("%I:%M %p")
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
    cur.execute("""
        SELECT id, required_hours
        FROM users
        WHERE messenger_id = %s
    """, (sender_id,))
    user = cur.fetchone()
    if not user:
        return "⚠️ Please REGISTER first. Reply REGISTER to begin."

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

    # Late count
    cur.execute("""
        SELECT COUNT(*) AS late_count
        FROM dtr_records
        WHERE user_id = %s
          AND is_late = TRUE
    """, (user_id,))
    late_count = int(cur.fetchone()["late_count"])

    # Missing time-outs (before today)
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
    latest_missing_date = missing["latest_missing_date"]

    required_minutes = required_hours * 60
    remaining_minutes = max(0, required_minutes - total_minutes)

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

def handle_admin_missing_today(cur, today_ph: date) -> str:
    cur.execute("""
        SELECT u.full_name, u.student_id, u.section
        FROM dtr_records r
        JOIN users u ON u.id = r.user_id
        WHERE r.date = %s
          AND r.time_in IS NOT NULL
          AND r.time_out IS NULL
        ORDER BY u.section, u.full_name
    """, (today_ph,))
    rows = cur.fetchall()

    if not rows:
        return f"✅ No students missing TIME OUT for {today_ph}."

    lines = [f"⚠️ Missing TIME OUT ({today_ph}):"]
    for r in rows:
        lines.append(
            f"- {r.get('full_name','')} "
            f"({r.get('student_id','')}) "
            f"[{r.get('section','')}]"
        )

    return "\n".join(lines)

# =========================================================
# Home
# =========================================================

@app.route("/")
def home():
    return "OJT DTR Bot Running"





