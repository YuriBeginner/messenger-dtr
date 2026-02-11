from flask import Flask, request, send_from_directory
from openpyxl import Workbook, load_workbook
from datetime import datetime, timezone, timedelta
import os
import json
import base64
import requests

app = Flask(__name__)
VERIFY_TOKEN = "ojt_dtr_token"

# ---------- FILES ----------
if not os.path.exists("DTR"):
    os.makedirs("DTR")

USERS_FILE = "users.json"

def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, "r") as f:
        return json.load(f)

def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f)

# ---------- EXCEL ----------
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

# ---------- GITHUB ----------
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
REPO = "YuriBeginner/messenger-dtr"

def upload_to_github(file_path, name):
    url = f"https://api.github.com/repos/{REPO}/contents/DTR/{name}.xlsx"

    with open(file_path, "rb") as f:
        content = base64.b64encode(f.read()).decode()

    r = requests.get(url, headers={"Authorization": f"token {GITHUB_TOKEN}"})
    sha = r.json().get("sha") if r.status_code == 200 else None

    data = {
        "message": f"Update DTR for {name}",
        "content": content,
        "branch": "main"
    }

    if sha:
        data["sha"] = sha

    requests.put(url, json=data, headers={
        "Authorization": f"token {GITHUB_TOKEN}",
        "Content-Type": "application/json"
    })

# ---------- LOG TIME ----------
def log_time(name, action, timestamp):
    ensure_file(name)
    f = get_file(name)
    wb = load_workbook(f)
    ws = wb.active

    utc_time = datetime.fromtimestamp(timestamp / 1000, tz=timezone.utc)
    ph_time = utc_time.astimezone(timezone(timedelta(hours=8)))

    date_str = ph_time.strftime("%Y-%m-%d")
    time_str = ph_time.strftime("%H:%M:%S")

    for row in ws.iter_rows(min_row=2):
        if row[0].value == name and row[1].value == date_str:

            if action == "TIME IN":
                return

            if action == "TIME OUT" and is_empty(row[3]):
                row[3].value = time_str
                wb.save(f)
                upload_to_github(f, name)
                return

            return

    if action == "TIME IN":
        ws.append([name, date_str, time_str, None])
        wb.save(f)
        upload_to_github(f, name)

# ---------- VERIFY WEBHOOK ----------
@app.route("/webhook", methods=["GET"])
def verify():
    token = request.args.get("hub.verify_token")
    challenge = request.args.get("hub.challenge")
    if token == VERIFY_TOKEN:
        return challenge
    return "Verification failed"

# ---------- WEBHOOK ----------
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

        # ----- REGISTER (LOCKED) -----
        if text.startswith("REGISTER "):
            if sender_id in users:
                print(f"{sender_id} tried to re-register. Ignored.")
                return "ok", 200

            real_name = raw_text.replace("REGISTER ", "").strip()
            users[sender_id] = real_name
            save_users(users)
            print(f"Registered {sender_id} as {real_name}")
            return "ok", 200

        # ----- FIXNAME (WORKING) -----
        if text.startswith("FIXNAME "):
            new_name = raw_text[8:].strip()
            old_name = users.get(sender_id)

            if old_name:
                old_file = get_file(old_name)
                new_file = get_file(new_name)

                if os.path.exists(old_file):
                    os.rename(old_file, new_file)
                    upload_to_github(new_file, new_name)

                users[sender_id] = new_name
                save_users(users)

                print(f"FIXNAME: {old_name} -> {new_name}")

            return "ok", 200

        # ----- GET NAME -----
        name = users.get(sender_id, sender_id)

        # ----- TIME IN / OUT -----
        if text in ["TIME IN", "TIME OUT"]:
            print(f"{name} -> {text}")
            log_time(name, text, timestamp)

    except Exception as e:
        print("Error:", e)

    return "ok", 200

# ---------- DOWNLOAD ----------
@app.route("/download/<name>")
def download_file(name):
    return send_from_directory("DTR", f"{name}.xlsx", as_attachment=True)

# ---------- PRIVACY ----------
@app.route("/privacy.html")
def privacy():
    return send_from_directory('.', 'privacy.html')

@app.route("/")
def home():
    return "OJT DTR Bot is running!"
