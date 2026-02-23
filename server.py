import csv
import io
import hmac
import hashlib
import base64
import time
import requests
import json
import os
import psycopg2
import secrets
import string
import time as _time
from psycopg2.extras import RealDictCursor
from psycopg2 import errors
from flask import Response
from flask import abort
from flask import Flask, request, render_template
from datetime import datetime, timezone, timedelta, date
from flask import session, redirect, url_for, abort
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps


app = Flask(__name__)

if __name__ == "__main__":
    app.run()
@app.context_processor
def inject_org_branding():
    org_id = session.get("org_id")
    if not org_id:
        return {"organization": None}

    try:
        conn = get_db_connection()
        try:
            with conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    org = get_org_branding(cur, org_id)
                    return {"organization": org}
        finally:
            try:
                conn.close()
            except Exception:
                pass
    except Exception:
        # ✅ Never crash page render if DB is down / env missing
        return {"organization": None}

    conn = get_db_connection()
    try:
        with conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                org = get_org_branding(cur, org_id)
                return {"organization": org}
    except Exception:
        return {"organization": None}
    finally:
        try:
            conn.close()
        except Exception:
            pass


VERIFY_TOKEN = "ojt_dtr_token"
PAGE_ACCESS_TOKEN = os.environ.get("PAGE_ACCESS_TOKEN")
DATABASE_URL = os.environ.get("DATABASE_URL")
CRON_SECRET = os.environ.get("CRON_SECRET")
DEFAULT_ORG_ID = int(os.environ.get("DEFAULT_ORG_ID", "0"))
EXPORT_SECRET = os.environ.get("EXPORT_SECRET", "")
SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY environment variable is required")
app.secret_key = SECRET_KEY
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=True,   # must be HTTPS in production
)
app.permanent_session_lifetime = timedelta(hours=8)


PH_TZ = timezone(timedelta(hours=8))
OFFICIAL_START_HOUR = 8
OFFICIAL_START_MINUTE = 0
GRACE_MINUTES = 10  # grace period for lateness
REG_SESSION_EXPIRY_MINUTES = 15
EXPORT_TOKEN_TTL_SECONDS = 300  # 5 minutes
MAX_LOGIN_ATTEMPTS = 5
LOGIN_LOCK_MINUTES = 10


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
# Secure Download Link Helper
# =========================================================

def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")

def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

def make_export_token(payload: dict) -> str:
    if not EXPORT_SECRET:
        raise RuntimeError("EXPORT_SECRET not set")

    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    sig = hmac.new(EXPORT_SECRET.encode("utf-8"), body, hashlib.sha256).digest()
    return f"{_b64url_encode(body)}.{_b64url_encode(sig)}"

def verify_export_token(token: str) -> dict | None:
    try:
        if not EXPORT_SECRET:
            return None
        b64_body, b64_sig = token.split(".", 1)
        body = _b64url_decode(b64_body)
        sig = _b64url_decode(b64_sig)

        expected = hmac.new(EXPORT_SECRET.encode("utf-8"), body, hashlib.sha256).digest()
        if not hmac.compare_digest(sig, expected):
            return None

        payload = json.loads(body.decode("utf-8"))
        exp = int(payload.get("exp", 0))
        if int(time.time()) > exp:
            return None
        return payload
    except Exception:
        return None
# =========================================================
# Org branding
# =========================================================

def get_org_branding(cur, org_id: int):
    cur.execute("""
        SELECT id, name, logo_url, primary_color, secondary_color
        FROM organizations
        WHERE id = %s
        LIMIT 1
    """, (org_id,))
    return cur.fetchone()

# =========================================================
# CSRF Helper function
# =========================================================

def get_csrf_token() -> str:
    tok = session.get("csrf_token")
    if not tok:
        tok = secrets.token_urlsafe(32)
        session["csrf_token"] = tok
    return tok

def csrf_validate_or_abort():
    # Accept token from form or headers
    sent = (request.form.get("csrf_token") or request.headers.get("X-CSRF-Token") or "")
    if not sent or sent != session.get("csrf_token"):
        abort(400)

@app.context_processor
def inject_csrf():
    return {"csrf_token": get_csrf_token()}


# =========================================================
# Email Login Security
# =========================================================
def _norm_email(email: str) -> str:
    return (email or "").strip().lower()

def login_attempt_get(cur, email: str):
    email = _norm_email(email)
    cur.execute("""
        SELECT email, failed_attempts, locked_until
        FROM admin_login_attempts
        WHERE email = %s
        LIMIT 1
    """, (email,))
    return cur.fetchone()

def login_attempt_record_failure(cur, email: str) -> bool:
    # ... your upsert/increment logic here ...
    # after increment, if attempts >= 5 -> set locked_until
    # return True if lock set, else False
    email = _norm_email(email)
    now_utc = datetime.now(timezone.utc)

    cur.execute("""
        INSERT INTO admin_login_attempts (email, failed_attempts, locked_until, updated_at)
        VALUES (%s, 1, NULL, now())
        ON CONFLICT (email)
        DO UPDATE SET
            failed_attempts = admin_login_attempts.failed_attempts + 1,
            updated_at = now()
        RETURNING failed_attempts
    """, (email,))
    attempts = int(cur.fetchone()["failed_attempts"])

    if attempts >= MAX_LOGIN_ATTEMPTS:
        locked_until = now_utc + timedelta(minutes=LOGIN_LOCK_MINUTES)
        cur.execute("""
            UPDATE admin_login_attempts
            SET locked_until = %s,
                updated_at = now()
            WHERE email = %s
        """, (locked_until, email))

def login_attempt_reset(cur, email: str):
    email = _norm_email(email)
    cur.execute("""
        DELETE FROM admin_login_attempts
        WHERE email = %s
    """, (email,))

def get_client_ip():
    # Render / proxies often set X-Forwarded-For
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        # first IP is original client
        return xff.split(",")[0].strip()
    return request.remote_addr

def get_user_agent():
    return request.headers.get("User-Agent", "")

# =========================================================
# Database
# =========================================================

def get_db_connection():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL env var is not set")

    last_err = None
    for attempt in range(4):
        try:
            return psycopg2.connect(
                DATABASE_URL,
                connect_timeout=10,
                keepalives=1,
                keepalives_idle=30,
                keepalives_interval=10,
                keepalives_count=5,
            )
        except psycopg2.OperationalError as e:
            last_err = e
            _time.sleep(0.6 * (2 ** attempt))  # 0.6, 1.2, 2.4, 4.8 sec
    raise last_err

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

def normalize_join_code(s: str) -> str:
    return (s or "").strip().upper()

def get_org_context(cur, messenger_id: str):
    cur.execute("""
        SELECT organization_id
        FROM messenger_org_context
        WHERE messenger_id = %s
    """, (messenger_id,))
    row = cur.fetchone()
    return row["organization_id"] if row else None

def set_org_context(cur, messenger_id: str, org_id: int):
    cur.execute("""
        INSERT INTO messenger_org_context (messenger_id, organization_id, updated_at)
        VALUES (%s, %s, now())
        ON CONFLICT (messenger_id)
        DO UPDATE SET organization_id = EXCLUDED.organization_id,
                      updated_at = now()
    """, (messenger_id, org_id))

def clear_org_context(cur, messenger_id: str):
    cur.execute("DELETE FROM messenger_org_context WHERE messenger_id=%s", (messenger_id,))

def resolve_join_code(cur, code: str):
    code = normalize_join_code(code)
    cur.execute("""
        SELECT jc.organization_id, o.name as org_name
        FROM org_join_codes jc
        JOIN organizations o ON o.id = jc.organization_id
        WHERE jc.code = %s
          AND jc.is_active = TRUE
          AND (jc.expires_at IS NULL OR now() <= jc.expires_at)
        LIMIT 1
    """, (code,))
    return cur.fetchone()  # None if invalid

def get_admin_scope_by_messenger(cur, sender_id: str):
    """
    Returns (admin_user_id, org_id) for an admin messenger user.
    """
    cur.execute("""
        SELECT id, organization_id, role
        FROM users
        WHERE messenger_id = %s
        LIMIT 1
    """, (sender_id,))
    u = cur.fetchone()
    if not u or u.get("role") != "admin":
        return None, None
    return u["id"], u["organization_id"]



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
        return f"⚠️ You are already registered as: {name}"

    # ✅ Require org context before registration
    org_id = get_org_context(cur, sender_id)
    if not org_id:
        return (
            "🏫 Before you REGISTER, you must JOIN your school.\n\n"
            "Reply like this:\n"
            "JOIN <CODE>\n\n"
            "Example:\n"
            "JOIN ABC123\n\n"
            "If you need help, contact your coordinator."
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
            # ✅ Must have org context (from JOIN CODE)
            org_id = get_org_context(cur, sender_id)
            if not org_id:
                reg_delete_session(cur, sender_id)
                return (
                    "⛔ Registration failed: No school linked.\n\n"
                    "Please send:\n"
                    "JOIN <CODE>\n\n"
                    "Then send:\n"
                    "REGISTER"
                )

            cur.execute("""
                INSERT INTO users
                  (messenger_id, full_name, student_id, course, section, company_name,
                   required_hours, start_date, end_date, role, organization_id, completion_status)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,'student',%s,'IN_PROGRESS')
            """, (
                sender_id,
                data["full_name"],
                data["student_id"],
                data["course"],
                data["section"],
                data["company_name"],
                int(data["required_hours"]),
                data["start_date"],
                data["end_date"],
                org_id
            ))
    
            reg_delete_session(cur, sender_id)
    
            # optional: clear org context after successful registration
            clear_org_context(cur, sender_id)
    
            return "✅ Registration successful! Commands: TIME IN, TIME OUT, STATUS"
    
        if txt.upper() == "NO":
            reg_delete_session(cur, sender_id)
            return "Okay. Reply REGISTER to start again."
    
        return "Please reply YES to confirm or NO to restart."

# =========================================================
# Log Admin Action
# =========================================================

def log_admin_action(cur, admin_user_id: int, action: str, target: str = None, metadata: dict = None):
    metadata = metadata or {}
    cur.execute("""
        INSERT INTO admin_activity_logs (admin_user_id, action, target, metadata)
        VALUES (%s, %s, %s, %s::jsonb)
    """, (admin_user_id, action, target, json.dumps(metadata)))

def admin_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if not session.get("admin_user_id"):
            return redirect(url_for("admin_login"))
        return view_func(*args, **kwargs)
    return wrapper


# =========================================================
# Temporary debug route
# =========================================================

@app.route("/admin/db-debug-org-joincodes")
@admin_required
def db_debug_org_joincodes():
    org_id = session.get("org_id")
    if not org_id:
        return {"ok": False, "error": "no org_id in session"}, 400

    conn = get_db_connection()
    try:
        with conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                # 1) table exists + columns check
                cur.execute("""
                    SELECT column_name, data_type
                    FROM information_schema.columns
                    WHERE table_schema='public'
                      AND table_name='org_join_codes'
                    ORDER BY ordinal_position
                """)
                cols = cur.fetchall()

                # 2) pull latest 5 rows
                cur.execute("""
                    SELECT id, organization_id, code, is_active, expires_at, created_at, created_by_admin_id
                    FROM org_join_codes
                    WHERE organization_id = %s
                    ORDER BY created_at DESC
                    LIMIT 5
                """, (org_id,))
                rows = cur.fetchall()

                return {"ok": True, "org_id": org_id, "columns": cols, "latest_rows": rows}, 200
    except Exception as e:
        return {"ok": False, "error": repr(e)}, 500
    finally:
        conn.close()


@app.errorhandler(400)
def bad_request(e):
    print("BAD_REQUEST:", repr(e))
    return "Bad Request", 400


# =========================================================
# Completion + Risk Helpers
# =========================================================

def recompute_completion(cur, user_id: int):
    """
    Recompute accumulated minutes and set completion fields if threshold reached.
    Idempotent: safe to call multiple times.
    """
    cur.execute("""
        SELECT required_hours, completed_at, completion_status
        FROM users
        WHERE id = %s
        FOR UPDATE
    """, (user_id,))
    u = cur.fetchone()
    if not u:
        return

    required_hours = int(u["required_hours"] or 240)
    required_minutes = required_hours * 60

    cur.execute("""
        SELECT COALESCE(SUM(COALESCE(minutes_worked, 0)), 0) AS total_minutes
        FROM dtr_records
        WHERE user_id = %s
    """, (user_id,))
    total_minutes = int(cur.fetchone()["total_minutes"] or 0)

    if total_minutes >= required_minutes:
        if u.get("completed_at") is None or (u.get("completion_status") != "COMPLETE"):
            cur.execute("""
                UPDATE users
                SET completed_at = COALESCE(completed_at, now()),
                    completion_status = 'COMPLETE'
                WHERE id = %s
            """, (user_id,))
    else:
        # We intentionally DO NOT revert COMPLETE -> IN_PROGRESS (audit stability).
        # If you want revert behavior, implement it explicitly.
        return

def clamp(x, lo, hi):
    return max(lo, min(hi, x))

def compute_risk_score(today_ph: date, end: date, required_hours: int,
                       total_minutes: int, missing_7d: int, late_14d: int, inactive_days: int):
    """
    Returns (risk_score, risk_level, reasons_dict)
    """
    required_hours = int(required_hours or 240)
    total_hours = total_minutes / 60.0
    remaining_hours = max(0.0, required_hours - total_hours)

    days_left = None
    if end:
        days_left = (end - today_ph).days

    score = 0
    reasons = {}

    # Missing timeouts last 7 days (cap 60)
    miss_pts = clamp(missing_7d * 20, 0, 60)
    if missing_7d:
        reasons["missing_timeouts_7d"] = missing_7d
        score += miss_pts

    # Late last 14 days (cap 25)
    late_pts = clamp(late_14d * 5, 0, 25)
    if late_14d:
        reasons["lates_14d"] = late_14d
        score += late_pts

    # Inactive days
    if inactive_days >= 7:
        score += 35
        reasons["inactive_days"] = inactive_days
    elif inactive_days >= 5:
        score += 20
        reasons["inactive_days"] = inactive_days
    elif inactive_days >= 3:
        score += 10
        reasons["inactive_days"] = inactive_days

    # Near end but still lots remaining
    if days_left is not None and days_left <= 10 and remaining_hours >= 40:
        score += 25
        reasons["behind_near_end"] = {"days_left": days_left, "remaining_hours": round(remaining_hours, 1)}

    score = clamp(score, 0, 100)

    if score >= 70:
        level = "HIGH"
    elif score >= 35:
        level = "MED"
    else:
        level = "LOW"

    return score, level, reasons
                           


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
                     # ==========================
                    # JOIN CODE (org binding)
                    # ==========================
                        if text.startswith("JOIN "):
                            code = raw_text.split(" ", 1)[1].strip()
                            found = resolve_join_code(cur, code)
                            if not found:
                                send_message(sender_id, "❌ Invalid join code. Please check with your coordinator.")
                                return "ok", 200
    
                            set_org_context(cur, sender_id, int(found["organization_id"]))
                            send_message(sender_id, f"✅ Joined: {found['org_name']}\nNow type: REGISTER")
                            return "ok", 200
    
                        if text == "JOIN":
                            send_message(sender_id, "Usage: JOIN <CODE>\nExample: JOIN ABC123")
                            return "ok", 200
                        if text == "REGISTER":
                            send_message(sender_id, start_registration(cur, sender_id))
                            return "ok", 200

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

                        cmd = " ".join(text.split())  # normalize spaces
                        parts = cmd.split()

                        # ADMIN HELP
                        if cmd == "ADMIN HELP":
                            send_message(sender_id, admin_help_text())
                            return "ok", 200

                        # ADMIN SUMMARY
                        if cmd == "ADMIN SUMMARY":
                            admin_user_id, org_id = get_admin_scope_by_messenger(cur, sender_id)
                            if not admin_user_id or not org_id:
                                send_message(sender_id, "⛔ Admin access required.")
                                return "ok", 200
                        
                            send_message(sender_id, handle_admin_summary(cur, today_ph, org_id))
                            return "ok", 200

                        # ADMIN MISSING TODAY [course] [section]
                        if cmd.startswith("ADMIN MISSING TODAY"):
                            # allowed:
                            # parts = ["ADMIN","MISSING","TODAY"]
                            # parts = ["ADMIN","MISSING","TODAY","BSECE"]
                            # parts = ["ADMIN","MISSING","TODAY","BSECE","4B"]
                            if len(parts) == 3:
                                course = None
                                section = None
                            elif len(parts) == 4:
                                course = parts[3].upper()
                                section = None
                            elif len(parts) == 5:
                                course = parts[3].upper()
                                section = parts[4].upper()
                            else:
                                send_message(sender_id, usage(
                                    "ADMIN MISSING TODAY",
                                    "ADMIN MISSING TODAY [course] [section]",
                                    "ADMIN MISSING TODAY BSECE 4B"
                                ))
                                return "ok", 200
                        
                            admin_user_id, org_id = get_admin_scope_by_messenger(cur, sender_id)
                            if not admin_user_id or not org_id:
                                send_message(sender_id, "⛔ Admin access required.")
                                return "ok", 200
                        
                            send_message(
                                sender_id,
                                handle_admin_missing_today(cur, today_ph, org_id, course=course, section=section)
                            )
                            return "ok", 200

                        # ADMIN RISK <course> <section>
                        if cmd.startswith("ADMIN RISK"):
                            if len(parts) != 4:
                                send_message(sender_id, usage("ADMIN RISK", "ADMIN RISK <course> <section>", "ADMIN RISK BSECE 4B"))
                                return "ok", 200
                        
                            admin_user_id, org_id = get_admin_scope_by_messenger(cur, sender_id)
                            if not admin_user_id or not org_id:
                                send_message(sender_id, "⛔ Admin access required.")
                                return "ok", 200
                        
                            course = parts[2].upper()
                            section = parts[3].upper()
                            send_message(sender_id, handle_admin_risk(cur, today_ph, org_id, course, section))
                            return "ok", 200

                        # ADMIN STUDENT <student_id>
                        if cmd.startswith("ADMIN STUDENT"):
                            if len(parts) != 3:
                                send_message(sender_id, usage("ADMIN STUDENT", "ADMIN STUDENT <student_id>", "ADMIN STUDENT 2020-12345"))
                                return "ok", 200
                        
                            admin_user_id, org_id = get_admin_scope_by_messenger(cur, sender_id)
                            if not admin_user_id or not org_id:
                                send_message(sender_id, "⛔ Admin access required.")
                                return "ok", 200
                        
                            student_id_input = parts[2].strip()
                            send_message(sender_id, handle_admin_student(cur, today_ph, org_id, student_id_input))
                            return "ok", 200

                        # ADMIN CLASS <course> <section>
                        if cmd.startswith("ADMIN CLASS"):
                            if len(parts) != 4:
                                send_message(sender_id, usage("ADMIN CLASS", "ADMIN CLASS <course> <section>", "ADMIN CLASS BSECE 4B"))
                                return "ok", 200
                        
                            admin_user_id, org_id = get_admin_scope_by_messenger(cur, sender_id)
                            if not admin_user_id or not org_id:
                                send_message(sender_id, "⛔ Admin access required.")
                                return "ok", 200
                        
                            course = parts[2].upper()
                            section = parts[3].upper()
                            send_message(sender_id, handle_admin_class(cur, today_ph, org_id, course, section))
                            return "ok", 200

                        # ADMIN SECTION <section>
                        if cmd.startswith("ADMIN SECTION"):
                            if len(parts) != 3:
                                send_message(sender_id, usage("ADMIN SECTION", "ADMIN SECTION <section>", "ADMIN SECTION 4B"))
                                return "ok", 200
                        
                            admin_user_id, org_id = get_admin_scope_by_messenger(cur, sender_id)
                            if not admin_user_id or not org_id:
                                send_message(sender_id, "⛔ Admin access required.")
                                return "ok", 200
                        
                            section = parts[2].upper()
                            send_message(sender_id, handle_admin_section(cur, today_ph, org_id, section))
                            return "ok", 200

                        # ADMIN EXPORT CLASS <course> <section>
                        if cmd.startswith("ADMIN EXPORT CLASS"):
                            if len(parts) != 5:
                                send_message(sender_id, usage(
                                    "ADMIN EXPORT CLASS",
                                    "ADMIN EXPORT CLASS <course> <section>",
                                    "ADMIN EXPORT CLASS BSECE 4B"
                                ))
                                return "ok", 200
                        
                            admin_user_id, org_id = get_admin_scope_by_messenger(cur, sender_id)
                            if not admin_user_id or not org_id:
                                send_message(sender_id, "⛔ Admin access required.")
                                return "ok", 200
                        
                            course = parts[3].upper()
                            section = parts[4].upper()
                        
                            payload = {
                                "org_id": org_id,
                                "admin_user_id": admin_user_id,
                                "course": course,
                                "section": section,
                                "exp": int(time.time()) + EXPORT_TOKEN_TTL_SECONDS
                            }
                        
                            token = make_export_token(payload)
                            link = f"https://{request.host}/export/class?token={token}"
                            send_message(sender_id, f"📄 Export ready (valid for 5 minutes):\n{link}")
                            return "ok", 200
                    
                        course = parts[3].upper()
                        section = parts[4].upper()
                    
                        admin_user_id, org_id = get_admin_scope_by_messenger(cur, sender_id)
                        if not admin_user_id or not org_id:
                            send_message(sender_id, "⛔ Admin access required.")
                            return "ok", 200
                    
                        payload = {
                            "org_id": org_id,
                            "admin_user_id": admin_user_id,
                            "course": course,
                            "section": section,
                            "exp": int(time.time()) + EXPORT_TOKEN_TTL_SECONDS
                        }
                    
                        token = make_export_token(payload)
                        link = f"https://{request.host}/export/class?token={token}"
                        send_message(sender_id, f"📄 Export ready (valid for 5 minutes):\n{link}")
                        return "ok", 200


                        # Unknown admin command (clean)
                        send_message(sender_id, "Unknown admin command. Type: ADMIN HELP")
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
# CSV Download Route
# =========================================================



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
# Cron: Risk Snapshot (GET + secret)
# =========================================================

@app.route("/cron/risk-snapshot", methods=["GET"])
def cron_risk_snapshot():
    secret = request.args.get("secret", "")
    if not CRON_SECRET or secret != CRON_SECRET:
        return "unauthorized", 401

    today_ph = datetime.now(PH_TZ).date()

    conn = get_db_connection()
    try:
        with conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT
                        u.id AS user_id,
                        u.required_hours,
                        u.start_date,
                        u.end_date,
                        COALESCE(SUM(COALESCE(r.minutes_worked,0)),0) AS total_minutes,
                        MAX(CASE WHEN r.time_in IS NOT NULL THEN r.date ELSE NULL END) AS last_timein_date
                    FROM users u
                    LEFT JOIN dtr_records r ON r.user_id = u.id
                    WHERE COALESCE(u.role,'student')='student'
                    GROUP BY u.id
                """)
                students = cur.fetchall()

                upserts = 0
                for s in students:
                    user_id = s["user_id"]
                    start = s.get("start_date")
                    end = s.get("end_date")

                    # Only snapshot for active OJT window
                    if start and today_ph < start:
                        continue
                    if end and today_ph > end:
                        continue

                    # Missing timeouts in last 7 days
                    cur.execute("""
                        SELECT COUNT(*) AS c
                        FROM dtr_records
                        WHERE user_id = %s
                          AND date >= %s
                          AND date <= %s
                          AND time_in IS NOT NULL
                          AND time_out IS NULL
                    """, (user_id, today_ph - timedelta(days=7), today_ph))
                    missing_7d = int(cur.fetchone()["c"])

                    # Late in last 14 days
                    cur.execute("""
                        SELECT COUNT(*) AS c
                        FROM dtr_records
                        WHERE user_id = %s
                          AND date >= %s
                          AND date <= %s
                          AND is_late = TRUE
                    """, (user_id, today_ph - timedelta(days=14), today_ph))
                    late_14d = int(cur.fetchone()["c"])

                    last_date = s.get("last_timein_date")
                    inactive_days = 999
                    if last_date:
                        inactive_days = (today_ph - last_date).days

                    score, level, reasons = compute_risk_score(
                        today_ph=today_ph,
                        end=end,
                        required_hours=int(s.get("required_hours") or 240),
                        total_minutes=int(s.get("total_minutes") or 0),
                        missing_7d=missing_7d,
                        late_14d=late_14d,
                        inactive_days=inactive_days
                    )

                    cur.execute("""
                        INSERT INTO risk_snapshots (user_id, snapshot_date, risk_score, risk_level, reasons)
                        VALUES (%s, %s, %s, %s, %s::jsonb)
                        ON CONFLICT (user_id, snapshot_date)
                        DO UPDATE SET risk_score = EXCLUDED.risk_score,
                                      risk_level = EXCLUDED.risk_level,
                                      reasons = EXCLUDED.reasons,
                                      created_at = now()
                    """, (user_id, today_ph, score, level, json.dumps(reasons)))
                    upserts += 1

        return {"date": str(today_ph), "upserts": upserts}, 200
    finally:
        conn.close()

@app.route("/health")
def health():
    return {"ok": True, "service": "ojt-management-portal"}, 200

@app.route("/debug/db")
def debug_db():
    try:
        conn = get_db_connection()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
                return {"db": "ok"}, 200
        finally:
            conn.close()
    except Exception as e:
        return {"db": "fail", "error": str(e)}, 500


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

    # ✅ Completion recompute AFTER update (correct placement)
    recompute_completion(cur, user_id)

    return f"✅ TIME OUT recorded at {utc_dt.astimezone(PH_TZ).strftime('%I:%M %p')} (Worked {fmt_hm(minutes_worked)})"


def handle_status(cur, sender_id: str, today_ph: date) -> str:
    cur.execute("""
        SELECT id, required_hours, completed_at, completion_status
        FROM users
        WHERE messenger_id = %s
    """, (sender_id,))
    user = cur.fetchone()
    if not user:
        return "⚠️ Please REGISTER first. Reply REGISTER to begin."

    user_id = user["id"]
    required_hours = int(user["required_hours"] or 240)

    # Completion line
    completion_status = user.get("completion_status") or "IN_PROGRESS"
    completed_at = user.get("completed_at")

    if completion_status == "COMPLETE":
        if completed_at:
            completed_ph = as_aware_utc(completed_at).astimezone(PH_TZ)
            completion_line = f"• Completion: ✅ COMPLETE ({completed_ph.strftime('%Y-%m-%d')})"
        else:
            completion_line = "• Completion: ✅ COMPLETE"
    else:
        completion_line = "• Completion: IN PROGRESS"

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
        f"{completion_line}\n"
        f"• Missing time-outs: {missing_count}\n"
        f"• Latest missing date: {latest_text}\n"
        f"• Late count: {late_count}"
    )

# =========================================================
# ADMIN portal route
# =========================================================

# =========================================================
# Log in/ Log out
# =========================================================

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "GET":
        return render_template("admin/login.html", error=None)

    email = _norm_email(request.form.get("email")) 
    password = request.form.get("password") or ""
    
    csrf_validate_or_abort()  # ✅ CSRF protection (keep this!)
    
    if not email or not password:
        return render_template("admin/login.html", error="Email and password are required.")
    
    conn = get_db_connection()
    try:
        with conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                # ✅ Check lock
                attempt = login_attempt_get(cur, email)
                now_utc = datetime.now(timezone.utc)
                
                if attempt and attempt.get("locked_until"):
                    locked_until = as_aware_utc(attempt["locked_until"])
                    if locked_until and now_utc < locked_until:
                        remaining = int((locked_until - now_utc).total_seconds())
                
                        return render_template(
                            "admin/login.html",
                            lock_seconds=remaining,
                            error=None
                        )
    
                # ✅ Look up admin account
                cur.execute("""
                    SELECT id, full_name, role, password_hash, organization_id
                    FROM users
                    WHERE email = %s
                    LIMIT 1
                """, (email,))
                u = cur.fetchone()
    
                # Invalid user / not admin / missing hash
                if (not u) or (u.get("role") != "admin") or (not u.get("password_hash")):
                    login_attempt_record_failure(cur, email)

                    log_admin_action(
                        cur,
                        u["id"],  # admin user id (since email exists)
                        "SECURITY_FAILED_LOGIN",
                        target=email,
                        metadata={"ip": ip, "ua": ua, "locked": bool(locked)}
                    )
                    
                    if locked:
                        log_admin_action(
                            cur,
                            u["id"],
                            "SECURITY_ACCOUNT_LOCKED",
                            target=email,
                            metadata={"ip": ip, "ua": ua, "lock_minutes": 10}
                        )
                    return render_template("admin/login.html", error="Invalid credentials.")
    
                # Wrong password
                if not check_password_hash(u["password_hash"], password):
                    ip = get_client_ip()
                    ua = get_user_agent()
                    login_attempt_record_failure(cur, email)
                    return render_template("admin/login.html", error="Invalid credentials.")
    
                # ✅ Success: reset attempts
                login_attempt_reset(cur, email)
    
                session["admin_user_id"] = u["id"]
                session["admin_name"] = u.get("full_name") or "Admin"
                session["org_id"] = u.get("organization_id")
                session.permanent = True  # if you enabled permanent lifetime
    
                ip = get_client_ip()
                ua = get_user_agent()
                
                log_admin_action(
                    cur,
                    u["id"],
                    "SECURITY_LOGIN_SUCCESS",
                    target=email,
                    metadata={"ip": ip, "ua": ua}
                )
                return redirect(url_for("admin_dashboard"))
    
    finally:
        conn.close()


@app.route("/admin/logout")
@admin_required
def admin_logout():
    admin_id = session.get("admin_user_id")
    conn = get_db_connection()
    try:
        with conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                if admin_id:
                    log_admin_action(cur, admin_id, "PORTAL_LOGOUT")
    finally:
        conn.close()

    session.clear()
    return redirect(url_for("admin_login"))

# =========================================================
# Dashboard
# =========================================================
@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    today_ph = datetime.now(PH_TZ).date()
    admin_id = session["admin_user_id"]
    org_id = session.get("org_id")
    start_7d = today_ph - timedelta(days=6)

    conn = get_db_connection()
    try:
        with conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                
            # ✅ totals (org scoped)
                cur.execute("""
                    SELECT COUNT(*) AS c
                    FROM users
                    WHERE COALESCE(role,'student')='student'
                      AND organization_id = %s
                """, (org_id,))
                total_students = int(cur.fetchone()["c"])
        
                # ✅ timed in today (org scoped via JOIN users)
                cur.execute("""
                    SELECT COUNT(DISTINCT r.user_id) AS c
                    FROM dtr_records r
                    JOIN users u ON u.id = r.user_id
                    WHERE r.date = %s
                      AND r.time_in IS NOT NULL
                      AND u.organization_id = %s
                """, (today_ph, org_id))
                timed_in_today = int(cur.fetchone()["c"])
    
                # ✅ missing time-out today
                cur.execute("""
                    SELECT COUNT(*) AS c
                    FROM dtr_records r
                    JOIN users u ON u.id = r.user_id
                    WHERE r.date = %s
                      AND r.time_in IS NOT NULL
                      AND r.time_out IS NULL
                      AND u.organization_id = %s
                """, (today_ph, org_id))
                missing_timeout_today = int(cur.fetchone()["c"])
        
                # ✅ late today
                cur.execute("""
                    SELECT COUNT(*) AS c
                    FROM dtr_records r
                    JOIN users u ON u.id = r.user_id
                    WHERE r.date = %s
                      AND r.is_late = TRUE
                      AND u.organization_id = %s
                """, (today_ph, org_id))
                late_today = int(cur.fetchone()["c"])

                # ✅ 7-day trend (Timed In + Late) — org scoped 
                cur.execute("""
                    SELECT r.date,
                           COUNT(DISTINCT r.user_id) FILTER (WHERE r.time_in IS NOT NULL) AS timed_in,
                           COUNT(*) FILTER (WHERE r.is_late = TRUE) AS late
                    FROM dtr_records r
                    JOIN users u ON u.id = r.user_id
                    WHERE r.date >= %s
                      AND r.date <= %s
                      AND u.organization_id = %s
                      AND COALESCE(u.role,'student')='student'
                    GROUP BY r.date
                    ORDER BY r.date ASC
                """, (start_7d, today_ph, org_id))
                
                trend_rows = cur.fetchall()
                
                # Build complete 7-day series (fill missing dates with 0)
                trend_map = {row["date"]: row for row in trend_rows}
                trend_labels = []
                trend_timed_in = []
                trend_late = []
                
                for i in range(7):
                    d = start_7d + timedelta(days=i)
                    trend_labels.append(d.strftime("%b %d"))  # e.g. Feb 19
                    row = trend_map.get(d) or {}
                    trend_timed_in.append(int(row.get("timed_in") or 0))
                    trend_late.append(int(row.get("late") or 0))

    
                # ✅ completed count
                cur.execute("""
                    SELECT COUNT(*) AS c
                    FROM users
                    WHERE COALESCE(role,'student')='student'
                      AND organization_id = %s
                      AND completion_status = 'COMPLETE'
                """, (org_id,))
                completed = int(cur.fetchone()["c"])
    
                # ✅ risk snapshot counts (scoped)
                cur.execute("""
                    SELECT
                        SUM(CASE WHEN rs.risk_level='HIGH' THEN 1 ELSE 0 END) AS high,
                        SUM(CASE WHEN rs.risk_level='MED'  THEN 1 ELSE 0 END) AS med,
                        SUM(CASE WHEN rs.risk_level='LOW'  THEN 1 ELSE 0 END) AS low
                    FROM risk_snapshots rs
                    JOIN users u ON u.id = rs.user_id
                    WHERE rs.snapshot_date = %s
                      AND u.organization_id = %s
                      AND COALESCE(u.role,'student')='student'
                """, (today_ph, org_id))
                
                rs = cur.fetchone() or {}
                high_risk = int(rs.get("high") or 0)
                med_risk  = int(rs.get("med") or 0)
                low_risk  = int(rs.get("low") or 0)

    
                last_updated = datetime.now(PH_TZ).strftime("%I:%M %p")
    
                # ✅ Top 5 HIGH risk today
                cur.execute("""
                    SELECT u.id, u.full_name, u.student_id, u.course, u.section,
                           COALESCE(rs.accumulated_hours, 0) AS accumulated_hours,
                           COALESCE(rs.expected_hours, 0) AS expected_hours
                    FROM risk_snapshots rs
                    JOIN users u ON u.id = rs.user_id
                    WHERE rs.snapshot_date = %s
                      AND rs.risk_level = 'HIGH'
                      AND COALESCE(u.role,'student')='student'
                      AND u.organization_id = %s
                    ORDER BY (COALESCE(rs.expected_hours,0) - COALESCE(rs.accumulated_hours,0)) DESC
                    LIMIT 5
                """, (today_ph, org_id))
                top_high_risk = cur.fetchall()
    
                # ✅ Missing TIME OUT today list
                cur.execute("""
                    SELECT u.id, u.full_name, u.student_id, u.course, u.section
                    FROM dtr_records r
                    JOIN users u ON u.id = r.user_id
                    WHERE r.date = %s
                      AND r.time_in IS NOT NULL
                      AND r.time_out IS NULL
                      AND COALESCE(u.role,'student')='student'
                      AND u.organization_id = %s
                    ORDER BY u.course, u.section, u.full_name
                    LIMIT 8
                """, (today_ph, org_id))
                missing_today_list = cur.fetchall()
    
                # ✅ Recently completed
                cur.execute("""
                    SELECT u.id, u.full_name, u.student_id, u.course, u.section, u.completed_at
                    FROM users u
                    WHERE COALESCE(u.role,'student')='student'
                      AND u.organization_id = %s
                      AND u.completion_status = 'COMPLETE'
                      AND u.completed_at IS NOT NULL
                    ORDER BY u.completed_at DESC
                    LIMIT 5
                """, (org_id,))
                recent_completed = cur.fetchall()
    
                log_admin_action(cur, admin_id, "PORTAL_DASHBOARD_VIEW", target=str(today_ph))

        return render_template(
            "admin/dashboard.html",
            page_title="Dashboard",
            subtitle=str(today_ph),
            last_updated=last_updated,
            active_page="dashboard",
    
            total_students=total_students,
            timed_in_today=timed_in_today,
            missing_timeout_today=missing_timeout_today,
            late_today=late_today,
            completed=completed,
            high_risk=high_risk,
            med_risk=med_risk,
            low_risk=low_risk,

            top_high_risk=top_high_risk,
            missing_today_list=missing_today_list,
            recent_completed=recent_completed,

            trend_labels=trend_labels,
            trend_timed_in=trend_timed_in,
            trend_late=trend_late,

            admin_name=session.get("admin_name", "Admin")
        )
    
    finally:
        conn.close()

# =========================================================
# Student List
# =========================================================
@app.route("/admin/students")
@admin_required
def admin_students():
    admin_id = session["admin_user_id"]
    org_id = session.get("org_id")

    course = (request.args.get("course") or "").strip().upper()
    section = (request.args.get("section") or "").strip().upper()
    q = (request.args.get("q") or "").strip()

    where = ["COALESCE(u.role,'student')='student'", "u.organization_id = %s"]
    params = [org_id]

    if course:
        where.append("UPPER(u.course) = %s")
        params.append(course)
    if section:
        where.append("UPPER(u.section) = %s")
        params.append(section)
    if q:
        where.append("(u.student_id ILIKE %s OR u.full_name ILIKE %s)")
        params.extend([f"%{q}%", f"%{q}%"])

    where_sql = " AND ".join(where)

    conn = get_db_connection()
    try:
        with conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                today_ph = datetime.now(PH_TZ).date()

                cur.execute(f"""
                    SELECT
                        u.id, u.full_name, u.student_id, u.course, u.section,
                        u.required_hours, u.completion_status,
                        COALESCE(SUM(COALESCE(r.minutes_worked,0)),0) AS total_minutes,
                        SUM(CASE WHEN r.is_late=TRUE THEN 1 ELSE 0 END) AS late_count,
                        SUM(CASE WHEN r.time_in IS NOT NULL AND r.time_out IS NULL AND r.date < %s THEN 1 ELSE 0 END) AS missing_count,
                        COALESCE(rs.risk_level, '—') AS risk_level
                    FROM users u
                    LEFT JOIN dtr_records r ON r.user_id = u.id
                    LEFT JOIN risk_snapshots rs
                      ON rs.user_id = u.id
                     AND rs.snapshot_date = %s
                    WHERE {where_sql}
                    GROUP BY u.id, rs.risk_level
                    ORDER BY u.course, u.section, u.full_name
                    LIMIT 300
                """, tuple([today_ph, today_ph] + params))
                rows = cur.fetchall()

                log_admin_action(
                    cur, admin_id,
                    "PORTAL_STUDENTS_VIEW",
                    target=f"{course} {section}".strip(),
                    metadata={"q": q}
                )

        for r in rows:
            req = int(r.get("required_hours") or 240)
            acc_h = (int(r.get("total_minutes") or 0)) / 60.0
            r["acc_hours"] = round(acc_h, 2)
            r["remaining_hours"] = round(max(0.0, req - acc_h), 2)

            if r.get("completion_status") == "COMPLETE":
                r["risk_level"] = "COMPLETE"

        return render_template(
            "admin/students.html",
            page_title="Students",
            subtitle="Filter, search, and review progress",
            last_updated=datetime.now(PH_TZ).strftime("%I:%M %p"),
            active_page="students",
            students=rows,
            course=course,
            section=section,
            q=q,
            admin_name=session.get("admin_name","Admin")
        )
    finally:
        conn.close()

# =========================================================
# Student Detail
# =========================================================

@app.route("/admin/student/<int:user_id>")
@admin_required
def admin_student_detail(user_id: int):
    admin_id = session["admin_user_id"]
    org_id = session.get("org_id")
    today_ph = datetime.now(PH_TZ).date()

    conn = get_db_connection()
    try:
        with conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                # ✅ Enforce tenant at the user level (critical)
                cur.execute("""
                    SELECT id, full_name, student_id, course, section, company_name,
                           required_hours, start_date, end_date,
                           completion_status, completed_at
                    FROM users
                    WHERE id = %s
                      AND COALESCE(role,'student')='student'
                      AND organization_id = %s
                """, (user_id, org_id))
                u = cur.fetchone()
                if not u:
                    abort(404)

                # ✅ Pull recent DTR (no org_id column needed on dtr_records)
                cur.execute("""
                    SELECT date, time_in, time_out, minutes_worked, is_late, late_minutes
                    FROM dtr_records
                    WHERE user_id = %s
                    ORDER BY date DESC
                    LIMIT 30
                """, (user_id,))
                recent = cur.fetchall()

                # ✅ Totals
                cur.execute("""
                    SELECT COALESCE(SUM(COALESCE(minutes_worked,0)),0) AS total_minutes
                    FROM dtr_records
                    WHERE user_id = %s
                """, (user_id,))
                total_minutes = int(cur.fetchone()["total_minutes"] or 0)

                log_admin_action(
                    cur,
                    admin_id,
                    "PORTAL_STUDENT_VIEW",
                    target=u.get("student_id") or str(user_id)
                )

        req = int(u.get("required_hours") or 240)
        acc_h = total_minutes / 60.0
        remaining_h = max(0.0, req - acc_h)

        return render_template(
            "admin/student_detail.html",
            page_title="Student",
            subtitle=u.get("student_id") or "",
            last_updated=datetime.now(PH_TZ).strftime("%I:%M %p"),
            active_page="students",

            u=u,
            recent=recent,
            acc_hours=round(acc_h, 2),
            remaining_hours=round(remaining_h, 2),
            today=today_ph,
            admin_name=session.get("admin_name","Admin")
        )
    finally:
        conn.close()


# =========================================================
# Export Page
# =========================================================

@app.route("/admin/exports", methods=["GET", "POST"])
@admin_required
def admin_exports():
    admin_id = session["admin_user_id"]
    org_id = session.get("org_id")

    link = None
    error = None

    if request.method == "POST":
        csrf_validate_or_abort()  # ✅ CSRF protection
        course = (request.form.get("course") or "").strip().upper()
        section = (request.form.get("section") or "").strip().upper()

        if not course or not section:
            error = "Course and Section are required."
        else:
            # ✅ bind token to org_id (multi-tenant safety)
            payload = {
                "org_id": org_id,
                "course": course,
                "section": section,
                "admin_user_id": admin_id,
                "exp": int(time.time()) + EXPORT_TOKEN_TTL_SECONDS
            }

            token = make_export_token(payload)
            link = f"https://{request.host}/export/class?token={token}"

            conn = get_db_connection()
            try:
                with conn:
                    with conn.cursor(cursor_factory=RealDictCursor) as cur:
                        log_admin_action(cur, admin_id, "PORTAL_EXPORT_CLASS", target=f"{course} {section}")
            finally:
                conn.close()

    return render_template(
        "admin/exports.html",
        page_title="Exports",
        subtitle="Generate secure CSV links",
        last_updated=datetime.now(PH_TZ).strftime("%I:%M %p"),
        active_page="exports",
        link=link,
        error=error,
        admin_name=session.get("admin_name","Admin")
    )

JOIN_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no O/0, no I/1

def generate_join_code(length: int = 8) -> str:
    return "".join(secrets.choice(JOIN_CODE_ALPHABET) for _ in range(length))


def get_or_create_org_join_code(cur, org_id: int, admin_id: int = None) -> dict:
    """
    Returns a join code ROW dict:
    {id, organization_id, code, is_active, expires_at, created_at, created_by_admin_id}
    Always returns a row (never a plain string).
    """

    # 1) Try existing active, not expired
    cur.execute("""
        SELECT id, organization_id, code, is_active, expires_at, created_at, created_by_admin_id
        FROM org_join_codes
        WHERE organization_id = %s
          AND is_active = TRUE
          AND (expires_at IS NULL OR now() <= expires_at)
        ORDER BY created_at DESC
        LIMIT 1
    """, (org_id,))
    row = cur.fetchone()
    if row:
        return row

    # 2) Deactivate old codes (safety)
    cur.execute("""
        UPDATE org_join_codes
        SET is_active = FALSE
        WHERE organization_id = %s
    """, (org_id,))

    # 3) Create new code with retry on UNIQUE(code) collisions
    for _ in range(20):
        code = generate_join_code(8)
        try:
            cur.execute("""
                INSERT INTO org_join_codes
                    (organization_id, code, is_active, expires_at, created_by_admin_id, created_at)
                VALUES
                    (%s, %s, TRUE, now() + interval '30 days', %s, now())
                RETURNING id, organization_id, code, is_active, expires_at, created_at, created_by_admin_id
            """, (org_id, code, admin_id))
            return cur.fetchone()
        except Exception:
            # likely UNIQUE(code) collision
            continue

    raise RuntimeError("Failed to generate join code (too many collisions)")

@app.route("/export/class")
def export_class_csv():
    token = request.args.get("token", "")
    payload = verify_export_token(token)
    
    if not payload:
        return "unauthorized", 401

    # ✅ token-bound scope (multi-tenant safe)
    org_id = payload.get("org_id")
    course = (payload.get("course") or "").strip().upper()
    section = (payload.get("section") or "").strip().upper()
    admin_user_id = payload.get("admin_user_id")


    if not org_id or not course or not section:
        return "unauthorized", 401

    today_ph = datetime.now(PH_TZ).date()

    conn = get_db_connection()
    try:
        with conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT
                        u.full_name,
                        u.student_id,
                        u.course,
                        u.section,
                        u.company_name,
                        u.required_hours,
                        u.start_date,
                        u.end_date,
                        u.completion_status,
                        u.completed_at,
                        COALESCE(SUM(COALESCE(r.minutes_worked,0)),0) AS total_minutes,
                        SUM(CASE WHEN r.is_late = TRUE THEN 1 ELSE 0 END) AS late_count,
                        SUM(CASE WHEN r.time_in IS NOT NULL
                                  AND r.time_out IS NULL
                                  AND r.date < %s
                                 THEN 1 ELSE 0 END) AS missing_timeout_count
                    FROM users u
                    LEFT JOIN dtr_records r ON r.user_id = u.id
                    WHERE COALESCE(u.role,'student')='student'
                      AND u.organization_id = %s
                      AND UPPER(u.course) = %s
                      AND UPPER(u.section) = %s
                    GROUP BY u.id
                    ORDER BY u.full_name
                """, (today_ph, org_id, course, section))
                rows = cur.fetchall()

                # Optional: audit log of download (recommended)
                # If you don't want to create a public "export download" log, you can remove this.
                log_admin_action(
                    cur,
                    admin_user_id,
                    "EXPORT_CLASS_DOWNLOAD",
                    target=f"{course} {section}",
                    metadata={"org_id": org_id}
                )


        # Build CSV in memory
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "Full Name","Student ID","Course","Section","Company",
            "Required Hours","Start Date","End Date",
            "Completion Status","Completed At (UTC)",
            "Accumulated Hours","Remaining Hours",
            "Late Count","Missing Time-outs (Past Days)"
        ])

        for r in rows:
            required_hours = int(r["required_hours"] or 240)
            total_minutes = int(r["total_minutes"] or 0)
            acc_hours = total_minutes / 60.0
            remaining = max(0.0, required_hours - acc_hours)

            writer.writerow([
                r.get("full_name",""),
                r.get("student_id",""),
                r.get("course",""),
                r.get("section",""),
                r.get("company_name",""),
                required_hours,
                r.get("start_date",""),
                r.get("end_date",""),
                r.get("completion_status","IN_PROGRESS"),
                r.get("completed_at",""),
                f"{acc_hours:.2f}",
                f"{remaining:.2f}",
                int(r.get("late_count") or 0),
                int(r.get("missing_timeout_count") or 0),
            ])

        csv_data = output.getvalue()
        filename = f"OJT_ORG{org_id}_{course}_{section}_export.csv"

        return Response(
            csv_data,
            mimetype="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'}
        )
    finally:
        conn.close()

# =========================================================
# Log page
# =========================================================

@app.route("/admin/logs")
@admin_required
def admin_logs():
    admin_id = session["admin_user_id"]
    org_id = session.get("org_id")

    conn = get_db_connection()
    try:
        with conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT l.created_at, l.action, l.target, u.full_name
                    FROM admin_activity_logs l
                    JOIN users u ON u.id = l.admin_user_id
                    WHERE u.organization_id = %s
                    ORDER BY l.created_at DESC
                    LIMIT 50
                """, (org_id,))
                rows = cur.fetchall()

                log_admin_action(cur, admin_id, "PORTAL_LOGS_VIEW")

        return render_template(
            "admin/logs.html",
            page_title="Logs",
            subtitle="Admin activity (org-scoped)",
            last_updated=datetime.now(PH_TZ).strftime("%I:%M %p"),
            active_page="logs",
            rows=rows,
            admin_name=session.get("admin_name", "Admin")
        )
        
    finally:
        conn.close()
# =========================================================
# ADMIN Org
# =========================================================

@app.route("/admin/organization", methods=["GET", "POST"])
@admin_required
def admin_organization():
    admin_id = session["admin_user_id"]
    org_id = session.get("org_id")

    error = None
    success = None

    conn = get_db_connection()
    try:
        with conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:

                try:
                    # --- LOAD ---
                    org = get_org_branding(cur, org_id)
                    join_code_row = get_or_create_org_join_code(cur, org_id, admin_id)

                    # --- POST ACTIONS ---
                    if request.method == "POST":
                        csrf_validate_or_abort()
                        action = (request.form.get("action") or "").strip()

                        if action == "save_branding":
                            logo_url = (request.form.get("logo_url") or "").strip()
                            primary_color = (request.form.get("primary_color") or "").strip()
                            secondary_color = (request.form.get("secondary_color") or "").strip()

                            if primary_color and not primary_color.startswith("#"):
                                error = "Primary color must be hex like #111827"
                            elif secondary_color and not secondary_color.startswith("#"):
                                error = "Secondary color must be hex like #3b82f6"
                            else:
                                cur.execute("""
                                    UPDATE organizations
                                    SET logo_url = NULLIF(%s,''),
                                        primary_color = NULLIF(%s,''),
                                        secondary_color = NULLIF(%s,'')
                                    WHERE id = %s
                                """, (logo_url, primary_color, secondary_color, org_id))
                                log_admin_action(cur, admin_id, "ORG_BRANDING_UPDATE")
                                success = "Branding updated."

                        elif action == "regen_join_code":
                            cur.execute("""
                                UPDATE org_join_codes
                                SET is_active = FALSE
                                WHERE organization_id = %s
                            """, (org_id,))

                            for _ in range(20):
                                code = generate_join_code(8)
                                try:
                                    cur.execute("""
                                        INSERT INTO org_join_codes
                                        (organization_id, code, is_active, expires_at,
                                         created_by_admin_id, created_at)
                                        VALUES (%s, %s, TRUE, now() + interval '30 days',
                                                %s, now())
                                    """, (org_id, code, admin_id))
                                    log_admin_action(cur, admin_id, "ORG_JOIN_CODE_REGENERATE")
                                    success = "Join code regenerated."
                                    break
                                except Exception:
                                    continue
                            else:
                                error = "Failed to regenerate join code. Try again."

                        elif action == "deactivate_join_code":
                            cur.execute("""
                                UPDATE org_join_codes
                                SET is_active = FALSE
                                WHERE organization_id = %s
                                  AND is_active = TRUE
                            """, (org_id,))
                            log_admin_action(cur, admin_id, "JOIN_CODE_DEACTIVATED")
                            success = "Join code deactivated."

                        elif action == "activate_join_code":
                            cur.execute("""
                                WITH latest AS (
                                    SELECT id
                                    FROM org_join_codes
                                    WHERE organization_id = %s
                                    ORDER BY id DESC
                                    LIMIT 1
                                )
                                UPDATE org_join_codes
                                SET is_active = TRUE
                                WHERE id IN (SELECT id FROM latest)
                            """, (org_id,))
                            log_admin_action(cur, admin_id, "JOIN_CODE_ACTIVATED")
                            success = "Join code activated."

                        else:
                            error = "Unknown action."

                        # Reload after POST
                        org = get_org_branding(cur, org_id)
                        join_code_row = get_or_create_org_join_code(cur, org_id, admin_id)

                    # --- Student count ---
                    cur.execute("""
                        SELECT COUNT(*) AS c
                        FROM users
                        WHERE organization_id = %s
                          AND COALESCE(role,'student')='student'
                    """, (org_id,))
                    student_count = int(cur.fetchone()["c"] or 0)

                    # --- Expiration ---
                    expires_at = join_code_row.get("expires_at") if join_code_row else None
                    days_remaining = None
                    if expires_at:
                        now = datetime.now(timezone.utc)
                        expires_at_utc = as_aware_utc(expires_at)
                        delta = expires_at_utc - now
                        days_remaining = max(delta.days, 0)

                    join_code = join_code_row.get("code") if join_code_row else None

                    return render_template(
                        "admin/organization.html",
                        page_title="Organization",
                        subtitle="Branding & onboarding",
                        last_updated=datetime.now(PH_TZ).strftime("%I:%M %p"),
                        active_page="organization",
                        admin_name=session.get("admin_name", "Admin"),
                        error=error,
                        success=success,
                        org=org,
                        join_code=join_code,
                        student_count=student_count,
                        days_remaining=days_remaining
                    )

                except Exception as e:
                    # ✅ This catches EVERYTHING in this route
                    conn.rollback()
                    print("ADMIN_ORG_FATAL:", repr(e))
                    error = f"Database error: {str(e)}"

                    # render safe fallback
                    return render_template(
                        "admin/organization.html",
                        page_title="Organization",
                        subtitle="Branding & onboarding",
                        last_updated=datetime.now(PH_TZ).strftime("%I:%M %p"),
                        active_page="organization",
                        admin_name=session.get("admin_name", "Admin"),
                        error=error,
                        success=None,
                        org=get_org_branding(cur, org_id),
                        join_code=None,
                        student_count=0,
                        days_remaining=None
                    )

    finally:
        conn.close()


# =========================================================
# ADMIN handlers
# =========================================================

def handle_admin_missing_today(cur, today_ph: date, org_id: int, course: str = None, section: str = None) -> str:
    where = [
        "r.date = %s",
        "r.time_in IS NOT NULL",
        "r.time_out IS NULL",
        "COALESCE(u.role,'student')='student'",
        "u.organization_id = %s"
    ]
    params = [today_ph, org_id]

    if course:
        where.append("UPPER(u.course) = %s")
        params.append(course.upper())

    if section:
        where.append("UPPER(u.section) = %s")
        params.append(section.upper())

    where_sql = " AND ".join(where)

    cur.execute(f"""
        SELECT u.full_name, u.student_id, u.course, u.section
        FROM dtr_records r
        JOIN users u ON u.id = r.user_id
        WHERE {where_sql}
        ORDER BY u.course, u.section, u.full_name
    """, tuple(params))
    rows = cur.fetchall()

    scope = "All"
    if course and section:
        scope = f"{course} {section}"
    elif course:
        scope = f"{course}"

    if not rows:
        return f"✅ No students missing TIME OUT today ({today_ph}) — Scope: {scope}"

    lines = [f"⚠️ Missing TIME OUT today ({today_ph}) — Scope: {scope}"]
    for r in rows[:25]:
        lines.append(
            f"- {r.get('full_name','')} ({r.get('student_id','')}) "
            f"[{r.get('course','')} {r.get('section','')}]"
        )

    if len(rows) > 25:
        lines.append(f"...and {len(rows) - 25} more")

    return "\n".join(lines)

def handle_admin_summary(cur, today_ph: date, org_id: int) -> str:
    # ✅ Students (org-scoped)
    cur.execute("""
        SELECT COUNT(*) AS total
        FROM users
        WHERE COALESCE(role,'student')='student'
          AND organization_id = %s
    """, (org_id,))
    total_students = int(cur.fetchone()["total"])

    # ✅ Timed in today (org-scoped via JOIN)
    cur.execute("""
        SELECT COUNT(DISTINCT r.user_id) AS count
        FROM dtr_records r
        JOIN users u ON u.id = r.user_id
        WHERE r.date = %s
          AND r.time_in IS NOT NULL
          AND u.organization_id = %s
          AND COALESCE(u.role,'student')='student'
    """, (today_ph, org_id))
    timed_in_today = int(cur.fetchone()["count"])

    # ✅ Missing TIME OUT today (org-scoped)
    cur.execute("""
        SELECT COUNT(*) AS count
        FROM dtr_records r
        JOIN users u ON u.id = r.user_id
        WHERE r.date = %s
          AND r.time_in IS NOT NULL
          AND r.time_out IS NULL
          AND u.organization_id = %s
          AND COALESCE(u.role,'student')='student'
    """, (today_ph, org_id))
    missing_today = int(cur.fetchone()["count"])

    # ✅ Late today (org-scoped)
    cur.execute("""
        SELECT COUNT(*) AS count
        FROM dtr_records r
        JOIN users u ON u.id = r.user_id
        WHERE r.date = %s
          AND r.is_late = TRUE
          AND u.organization_id = %s
          AND COALESCE(u.role,'student')='student'
    """, (today_ph, org_id))
    late_today = int(cur.fetchone()["count"])

    # ✅ Completed (org-scoped)
    cur.execute("""
        SELECT COUNT(*) AS c
        FROM users
        WHERE COALESCE(role,'student')='student'
          AND organization_id = %s
          AND completion_status = 'COMPLETE'
    """, (org_id,))
    completed = int(cur.fetchone()["c"])

    # ✅ At risk from snapshots (org-scoped)
    cur.execute("""
        SELECT COUNT(*) AS c
        FROM risk_snapshots rs
        JOIN users u ON u.id = rs.user_id
        WHERE rs.snapshot_date = %s
          AND COALESCE(u.role,'student')='student'
          AND u.organization_id = %s
          AND rs.risk_level IN ('MED','HIGH')
    """, (today_ph, org_id))
    at_risk = int(cur.fetchone()["c"])

    return (
        f"📊 OJT Dashboard ({today_ph})\n\n"
        f"🏫 Org ID: {org_id}\n"
        f"👥 Students: {total_students}\n"
        f"🟢 Timed In Today: {timed_in_today}\n"
        f"⚠️ Missing TIME OUT: {missing_today}\n"
        f"⏰ Late Today: {late_today}\n\n"
        f"🎯 Completed: {completed}\n"
        f"🚨 At Risk (MED/HIGH): {at_risk}\n\n"
        f"Note: Risk depends on daily snapshot cron (/cron/risk-snapshot)."
    )

def handle_admin_risk(cur, today_ph: date, org_id: int, course: str, section: str) -> str:
    cur.execute("""
        SELECT u.full_name, u.student_id, rs.risk_score, rs.risk_level, rs.reasons
        FROM risk_snapshots rs
        JOIN users u ON u.id = rs.user_id
        WHERE rs.snapshot_date = %s
          AND COALESCE(u.role,'student')='student'
          AND u.organization_id = %s
          AND UPPER(u.course) = %s
          AND UPPER(u.section) = %s
        ORDER BY rs.risk_score DESC, u.full_name
        LIMIT 10
    """, (today_ph, org_id, course.upper(), section.upper()))
    rows = cur.fetchall()

    if not rows:
        return (
            f"📍 Risk ({course} {section}) — {today_ph}\n"
            f"🏫 Org ID: {org_id}\n"
            "No snapshot yet. Run /cron/risk-snapshot first."
        )

    lines = [f"🚨 Risk Dashboard: {course} {section} ({today_ph})", f"🏫 Org ID: {org_id}", ""]
    for r in rows:
        reasons = r.get("reasons") or {}
        reason_bits = []
        if "missing_timeouts_7d" in reasons:
            reason_bits.append(f"missing7d={reasons['missing_timeouts_7d']}")
        if "lates_14d" in reasons:
            reason_bits.append(f"late14d={reasons['lates_14d']}")
        if "inactive_days" in reasons:
            reason_bits.append(f"inactive={reasons['inactive_days']}d")
        if "behind_near_end" in reasons:
            b = reasons["behind_near_end"]
            reason_bits.append(f"near_end({b.get('days_left')}d,left {b.get('remaining_hours')}h)")

        why = ("; ".join(reason_bits)) if reason_bits else "—"
        lines.append(
            f"- {r.get('full_name','')} ({r.get('student_id','')}): "
            f"{r.get('risk_level','—')} {r.get('risk_score','—')}/100 — {why}"
        )

    return "\n".join(lines)

def handle_admin_student(cur, today_ph: date, org_id: int, student_id_input: str) -> str:
    # ✅ org-scoped student lookup
    cur.execute("""
        SELECT id, full_name, student_id, course, section,
               required_hours, start_date, end_date,
               completion_status, completed_at
        FROM users
        WHERE student_id = %s
          AND COALESCE(role,'student')='student'
          AND organization_id = %s
        LIMIT 1
    """, (student_id_input, org_id))
    student = cur.fetchone()

    if not student:
        return "❌ Student not found in your organization."

    user_id = student["id"]
    required_hours = int(student["required_hours"] or 240)

    # Totals
    cur.execute("""
        SELECT COALESCE(SUM(COALESCE(minutes_worked,0)),0) AS total_minutes
        FROM dtr_records
        WHERE user_id = %s
    """, (user_id,))
    total_minutes = int(cur.fetchone()["total_minutes"] or 0)
    accumulated_hours = total_minutes / 60.0
    remaining_hours = max(0.0, required_hours - accumulated_hours)

    # Late count
    cur.execute("""
        SELECT COUNT(*) AS late_count
        FROM dtr_records
        WHERE user_id = %s
          AND is_late = TRUE
    """, (user_id,))
    late_count = int(cur.fetchone()["late_count"] or 0)

    # Missing time-outs (all-time)
    cur.execute("""
        SELECT COUNT(*) AS missing_count
        FROM dtr_records
        WHERE user_id = %s
          AND time_in IS NOT NULL
          AND time_out IS NULL
    """, (user_id,))
    missing_count = int(cur.fetchone()["missing_count"] or 0)

    # Latest risk snapshot (optional but useful)
    cur.execute("""
        SELECT risk_level, risk_score
        FROM risk_snapshots
        WHERE user_id = %s
          AND snapshot_date = %s
        LIMIT 1
    """, (user_id, today_ph))
    rs = cur.fetchone() or {}
    risk_level = rs.get("risk_level") or "—"
    risk_score = rs.get("risk_score")
    risk_text = f"{risk_level}" + (f" ({risk_score}/100)" if risk_score is not None else "")

    completion_status = student.get("completion_status") or "IN_PROGRESS"
    status_line = "🟢 IN PROGRESS"
    if completion_status == "COMPLETE":
        status_line = "✅ COMPLETE"

    start = student.get("start_date")
    end = student.get("end_date")

    return (
        f"👤 Student Overview\n\n"
        f"🏫 Org ID: {org_id}\n"
        f"Name: {student.get('full_name','')}\n"
        f"Student ID: {student.get('student_id','')}\n"
        f"Course/Section: {student.get('course','')} {student.get('section','')}\n\n"
        f"OJT Period: {start} to {end}\n\n"
        f"📊 Progress\n"
        f"• Accumulated: {accumulated_hours:.1f}h\n"
        f"• Remaining: {remaining_hours:.1f}h (of {required_hours}h)\n"
        f"• Late Count: {late_count}\n"
        f"• Missing Time-outs: {missing_count}\n"
        f"• Risk Today: {risk_text}\n\n"
        f"🎯 Status: {status_line}"
    )

def handle_admin_section(cur, today_ph: date, org_id: int, section: str) -> str:
    section = (section or "").upper().strip()

    # Total students in this section (org-scoped)
    cur.execute("""
        SELECT COUNT(*) AS total
        FROM users
        WHERE COALESCE(role,'student')='student'
          AND organization_id = %s
          AND UPPER(section) = %s
    """, (org_id, section))
    total_students = int(cur.fetchone()["total"] or 0)
    if total_students == 0:
        return f"❌ No students found in section {section} (Org {org_id})."

    # Timed in today
    cur.execute("""
        SELECT COUNT(DISTINCT r.user_id) AS count
        FROM dtr_records r
        JOIN users u ON u.id = r.user_id
        WHERE r.date = %s
          AND r.time_in IS NOT NULL
          AND COALESCE(u.role,'student')='student'
          AND u.organization_id = %s
          AND UPPER(u.section) = %s
    """, (today_ph, org_id, section))
    timed_in_today = int(cur.fetchone()["count"] or 0)

    # Missing time out today list
    cur.execute("""
        SELECT u.full_name, u.student_id, u.course
        FROM dtr_records r
        JOIN users u ON u.id = r.user_id
        WHERE r.date = %s
          AND r.time_in IS NOT NULL
          AND r.time_out IS NULL
          AND COALESCE(u.role,'student')='student'
          AND u.organization_id = %s
          AND UPPER(u.section) = %s
        ORDER BY u.course, u.full_name
    """, (today_ph, org_id, section))
    missing_rows = cur.fetchall()
    missing_count = len(missing_rows)

    # Completed count
    cur.execute("""
        SELECT COUNT(*) AS c
        FROM users
        WHERE COALESCE(role,'student')='student'
          AND organization_id = %s
          AND UPPER(section) = %s
          AND completion_status = 'COMPLETE'
    """, (org_id, section))
    completed = int(cur.fetchone()["c"] or 0)

    # At-risk (MED/HIGH)
    cur.execute("""
        SELECT COUNT(*) AS c
        FROM risk_snapshots rs
        JOIN users u ON u.id = rs.user_id
        WHERE rs.snapshot_date = %s
          AND rs.risk_level IN ('MED','HIGH')
          AND COALESCE(u.role,'student')='student'
          AND u.organization_id = %s
          AND UPPER(u.section) = %s
    """, (today_ph, org_id, section))
    at_risk = int(cur.fetchone()["c"] or 0)

    lines = [
        f"📌 Section Dashboard: {section} ({today_ph})",
        f"🏫 Org ID: {org_id}",
        "",
        f"👥 Students: {total_students}",
        f"🟢 Timed In Today: {timed_in_today}",
        f"⚠️ Missing TIME OUT: {missing_count}",
        f"🎯 Completed: {completed}",
        f"🚨 At Risk (MED/HIGH): {at_risk}",
    ]

    if missing_count > 0:
        lines.append("")
        lines.append("⚠️ Missing TIME OUT list:")
        for r in missing_rows[:10]:
            lines.append(f"- {r.get('full_name','')} ({r.get('student_id','')}) [{r.get('course','')}]")
        if missing_count > 10:
            lines.append(f"...and {missing_count - 10} more")

    return "\n".join(lines)

def handle_admin_class(cur, today_ph: date, org_id: int, course: str, section: str) -> str:
    course = (course or "").upper().strip()
    section = (section or "").upper().strip()

    # Total students in class (org-scoped)
    cur.execute("""
        SELECT COUNT(*) AS total
        FROM users
        WHERE COALESCE(role,'student')='student'
          AND organization_id = %s
          AND UPPER(course) = %s
          AND UPPER(section) = %s
    """, (org_id, course, section))
    total_students = int(cur.fetchone()["total"] or 0)
    if total_students == 0:
        return f"❌ No students found in {course} {section} (Org {org_id})."

    # Timed in today
    cur.execute("""
        SELECT COUNT(DISTINCT r.user_id) AS count
        FROM dtr_records r
        JOIN users u ON u.id = r.user_id
        WHERE r.date = %s
          AND r.time_in IS NOT NULL
          AND COALESCE(u.role,'student')='student'
          AND u.organization_id = %s
          AND UPPER(u.course) = %s
          AND UPPER(u.section) = %s
    """, (today_ph, org_id, course, section))
    timed_in_today = int(cur.fetchone()["count"] or 0)

    # Missing TIME OUT today list
    cur.execute("""
        SELECT u.full_name, u.student_id
        FROM dtr_records r
        JOIN users u ON u.id = r.user_id
        WHERE r.date = %s
          AND r.time_in IS NOT NULL
          AND r.time_out IS NULL
          AND COALESCE(u.role,'student')='student'
          AND u.organization_id = %s
          AND UPPER(u.course) = %s
          AND UPPER(u.section) = %s
        ORDER BY u.full_name
    """, (today_ph, org_id, course, section))
    missing_rows = cur.fetchall()
    missing_count = len(missing_rows)

    # Completed count (org-scoped)
    cur.execute("""
        SELECT COUNT(*) AS c
        FROM users
        WHERE COALESCE(role,'student')='student'
          AND organization_id = %s
          AND UPPER(course) = %s
          AND UPPER(section) = %s
          AND completion_status = 'COMPLETE'
    """, (org_id, course, section))
    completed = int(cur.fetchone()["c"] or 0)

    # At-risk (MED/HIGH) from snapshot (org-scoped)
    cur.execute("""
        SELECT COUNT(*) AS c
        FROM risk_snapshots rs
        JOIN users u ON u.id = rs.user_id
        WHERE rs.snapshot_date = %s
          AND rs.risk_level IN ('MED','HIGH')
          AND COALESCE(u.role,'student')='student'
          AND u.organization_id = %s
          AND UPPER(u.course) = %s
          AND UPPER(u.section) = %s
    """, (today_ph, org_id, course, section))
    at_risk = int(cur.fetchone()["c"] or 0)

    title = f"{course} {section}".strip()
    lines = [
        f"📌 Class Dashboard: {title} ({today_ph})",
        f"🏫 Org ID: {org_id}",
        "",
        f"👥 Students: {total_students}",
        f"🟢 Timed In Today: {timed_in_today}",
        f"⚠️ Missing TIME OUT: {missing_count}",
        f"🎯 Completed: {completed}",
        f"🚨 At Risk (MED/HIGH): {at_risk}",
    ]

    if missing_count > 0:
        lines.append("")
        lines.append("⚠️ Missing TIME OUT list:")
        for r in missing_rows[:10]:
            lines.append(f"- {r.get('full_name','')} ({r.get('student_id','')})")
        if missing_count > 10:
            lines.append(f"...and {missing_count - 10} more")

    return "\n".join(lines)
# =========================================================
# Home
# =========================================================

@app.template_filter("ph_dt")
def ph_dt_filter(dt):
    if not dt:
        return "—"
    dt = as_aware_utc(dt)
    return dt.astimezone(PH_TZ).strftime("%Y-%m-%d %I:%M %p")


@app.route("/privacy")
def privacy():
    return render_template("privacy.html")

@app.route("/")
def home():
    return "OJT DTR Bot Running"






















































