from flask import Flask, request
from datetime import datetime, timezone, timedelta
import os
import psycopg2
from psycopg2.extras import RealDictCursor
import requests

app = Flask(__name__)

VERIFY_TOKEN = "ojt_dtr_token"
PAGE_ACCESS_TOKEN = os.environ.get("PAGE_ACCESS_TOKEN")
DATABASE_URL = os.environ.get("DATABASE_URL")

# =========================================================
# ------------------- DATABASE ----------------------------
# =========================================================

def get_db_connection():
    return psycopg2.connect(DATABASE_URL)

# =========================================================
# ------------------- MESSENGER ---------------------------
# =========================================================

def send_message(psid, message):
    url = f"https://graph.facebook.com/v19.0/me/messages?access_token={PAGE_ACCESS_TOKEN}"

    payload = {
        "recipient": {"id": psid},
        "message": {"text": message}
    }

    requests.post(url, json=payload)

# =========================================================
# ------------------- VERIFY WEBHOOK ----------------------
# =========================================================

@app.route("/webhook", methods=["GET"])
def verify():
    token = request.args.get("hub.verify_token")
    challenge = request.args.get("hub.challenge")

    if token == VERIFY_TOKEN:
        return challenge

    return "Verification failed"

# =========================================================
# ------------------- WEBHOOK POST ------------------------
# =========================================================

@app.route("/webhook", methods=["POST"])
def webhook():
    data = request.json

    try:
        entry = data["entry"][0]
        messaging = entry["messaging"][0]

        if "message" not in messaging:
            return "ok", 200

        message_id = messaging["message"]["mid"]
        sender_id = messaging["sender"]["id"]
        raw_text = messaging["message"]["text"].strip()
        text = raw_text.upper()
        timestamp = messaging["timestamp"]

        # =================================================
        # Deduplication (Database-based)
        # =================================================

        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute(
            "SELECT mid FROM processed_messages WHERE mid = %s",
            (message_id,)
        )
        if cur.fetchone():
            cur.close()
            conn.close()
            print("Duplicate ignored:", message_id)
            return "ok", 200

        cur.execute(
            "INSERT INTO processed_messages (mid) VALUES (%s)",
            (message_id,)
        )
        conn.commit()
        cur.close()
        conn.close()


        if text == "REGISTER FORMAT":
            send_message(sender_id,
        """📝 OJT Registration Format:

        REGISTER    
        Name: Your Full Name
        StudentID: Your ID
        Course: BSIT
        Section: 4A    
        Company: Company Name
        RequiredHours: 240
        Start: YYYY-MM-DD
        End: YYYY-MM-DD
        """)
            return "ok", 200

        # ----- REGISTER -----
        if text.startswith("REGISTER"):

    # If only REGISTER was typed → show format
            if raw_text.strip().upper() == "REGISTER":
                send_message(sender_id,
        """📝 OJT Registration Format:

        REGISTER
        Name: Your Full Name
        StudentID: Your ID
        Course: BSIT
        Section: 4A
        Company: Company Name
        RequiredHours: 240
        Start: YYYY-MM-DD
        End: YYYY-MM-DD
        """)
                return "ok", 200

            # Otherwise → process registration
            try:
                lines = raw_text.split("\n")[1:]

                data = {}
                for line in lines:
                    key, value = line.split(":", 1)
                    data[key.strip().lower()] = value.strip()

                conn = get_db_connection()
                cur = conn.cursor()

                # Check if already registered
                cur.execute(
                    "SELECT id FROM users WHERE messenger_id = %s",
                    (sender_id,)
                )

                if cur.fetchone():
                    send_message(sender_id, "⚠️ You are already registered.")
                    cur.close()
                    conn.close()
                    return "ok", 200

                # Insert new user
                cur.execute("""
                    INSERT INTO users
                    (messenger_id, full_name, student_id, course, section,
                     company_name, required_hours, start_date, end_date)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """, (
                    sender_id,
                    data.get("name"),
                    data.get("studentid"),
                    data.get("course"),
                    data.get("section"),
                    data.get("company"),
                    int(data.get("requiredhours", 240)),
                    data.get("start"),
                    data.get("end")
                ))

                conn.commit()
                cur.close()
                conn.close()

                send_message(sender_id, "✅ Registration successful!")

            except Exception as e:
                print("Register error:", e)
                send_message(sender_id, "⚠️ Registration format incorrect. Type REGISTER to see format.")

            return "ok", 200

        # =================================================
        # TIME IN / TIME OUT
        # =================================================

        if text in ["TIME IN", "TIME OUT"]:

            conn = get_db_connection()
            cur = conn.cursor(cursor_factory=RealDictCursor)

            # Get user
            cur.execute(
                "SELECT id, full_name FROM users WHERE messenger_id = %s",
                (sender_id,)
            )
            user = cur.fetchone()

            if not user:
                cur.close()
                conn.close()
                send_message(sender_id, "⚠️ Please REGISTER first:\nREGISTER Your Full Name")
                return "ok", 200

            user_id = user["id"]

            # Convert to PH time
            utc_time = datetime.fromtimestamp(timestamp / 1000, tz=timezone.utc)
            ph_time = utc_time.astimezone(timezone(timedelta(hours=8)))
            today = ph_time.date()

            # Check existing record
            cur.execute(
                "SELECT * FROM dtr_records WHERE user_id = %s AND date = %s",
                (user_id, today)
            )
            record = cur.fetchone()

            # -------- TIME IN --------
            if text == "TIME IN":

                if record:
                    cur.close()
                    conn.close()
                    send_message(sender_id, "⚠️ TIME IN already recorded.")
                    return "ok", 200

                cur.execute(
                    "INSERT INTO dtr_records (user_id, date, time_in) VALUES (%s, %s, %s)",
                    (user_id, today, ph_time)
                )

                conn.commit()
                cur.close()
                conn.close()

                send_message(sender_id, f"✅ TIME IN recorded at {ph_time.strftime('%H:%M:%S')}")
                return "ok", 200

            # -------- TIME OUT --------
            if text == "TIME OUT":

                if not record:
                    cur.close()
                    conn.close()
                    send_message(sender_id, "⚠️ You must TIME IN first.")
                    return "ok", 200

                if record["time_out"] is not None:
                    cur.close()
                    conn.close()
                    send_message(sender_id, "⚠️ TIME OUT already recorded.")
                    return "ok", 200

                cur.execute(
                    "UPDATE dtr_records SET time_out = %s WHERE id = %s",
                    (ph_time, record["id"])
                )

                conn.commit()
                cur.close()
                conn.close()

                send_message(sender_id, f"✅ TIME OUT recorded at {ph_time.strftime('%H:%M:%S')}")
                return "ok", 200

    except Exception as e:
        print("Error:", e)

    return "ok", 200

# =========================================================
# ------------------- HOME -------------------------------
# =========================================================

@app.route("/")
def home():
    return "DTR Bot (PostgreSQL Version) Running"

