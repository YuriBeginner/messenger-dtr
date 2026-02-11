from flask import Flask, request
from openpyxl import Workbook, load_workbook
from datetime import datetime
import os
import json

USERS_FILE = "users.json"

def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, "r") as f:
        return json.load(f)

def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f)


app = Flask(__name__)
VERIFY_TOKEN = "ojt_dtr_token"

# ---------- EXCEL SETUP ----------
if not os.path.exists("DTR"):
    os.makedirs("DTR")

def get_file(name):
    return f"DTR/{name}.xlsx"

def ensure_file(name):
    f = get_file(name)
    if not os.path.exists(f):
        wb = Workbook()
        ws = wb.active
        ws.append(["Name", "Date", "Time In", "Time Out"])
        wb.save(f)

def is_empty(cell):
    return cell.value is None or str(cell.value).strip() == ""

def log_time(name, action, timestamp):
    ensure_file(name)
    f = get_file(name)
    wb = load_workbook(f)
    ws = wb.active

    dt = datetime.fromtimestamp(timestamp / 1000)
    date = dt.strftime("%Y-%m-%d")
    t = dt.strftime("%H:%M:%S")

    for row in ws.iter_rows(min_row=2):
        if row[0].value == name and row[1].value == date:
            if action == "TIME IN":
                return
            if action == "TIME OUT" and is_empty(row[3]):
                row[3].value = t
                wb.save(f)
                return
            if action == "TIME OUT":
                return

    if action == "TIME IN":
        ws.append([name, date, t, None])
        wb.save(f)

# ---------- VERIFY WEBHOOK ----------
@app.route("/webhook", methods=["GET"])
def verify():
    token = request.args.get("hub.verify_token")
    challenge = request.args.get("hub.challenge")

    if token == VERIFY_TOKEN:
        return challenge
    return "Verification failed"

# ---------- RECEIVE MESSAGES ----------
@app.route("/webhook", methods=["POST"])
def webhook():
    data = request.json

    try:
        entry = data["entry"][0]
        messaging = entry["messaging"][0]

        sender_id = messaging["sender"]["id"]
        raw_text = messaging["message"]["text"].strip()
        text = raw_text.upper()
        timestamp = messaging["timestamp"]

        users = load_users()

        # ----- REGISTER FEATURE -----
        if text.startswith("REGISTER "):
            real_name = raw_text.replace("REGISTER ", "").strip()
            users[sender_id] = real_name
            save_users(users)
            print(f"Registered {sender_id} as {real_name}")
            return "ok", 200

        # ----- GET REGISTERED NAME -----
        name = users.get(sender_id, sender_id)

        # ----- TIME IN / OUT -----
        if text in ["TIME IN", "TIME OUT"]:
            print(f"{name} -> {text}")
            log_time(name, text, timestamp)

    except Exception as e:
        print("Error:", e)

    return "ok", 200


@app.route("/", methods=["GET"])
def home():
    return "OJT DTR Bot is running!"


