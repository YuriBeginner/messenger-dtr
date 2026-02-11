from flask import Flask, request
from openpyxl import Workbook, load_workbook
from datetime import datetime
import os

app = Flask(__name__)

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

def log_time(name, action):
    ensure_file(name)
    f = get_file(name)
    wb = load_workbook(f)
    ws = wb.active

    date = datetime.now().strftime("%Y-%m-%d")
    t = datetime.now().strftime("%H:%M:%S")

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

# ---------- WEBHOOK ----------
@app.route("/", methods=["GET"])
def verify():
    return "Webhook server running."

@app.route("/", methods=["POST"])
def receive():
    data = request.json

    try:
        entry = data["entry"][0]
        messaging = entry["messaging"][0]
        sender_name = messaging["sender"]["name"]
        message_text = messaging["message"]["text"].strip().upper()

        if message_text in ["TIME IN", "TIME OUT"]:
            print(f"{sender_name} -> {message_text}")
            log_time(sender_name, message_text)

    except Exception as e:
        print("Error:", e)

    return "ok", 200

if __name__ == "__main__":
    app.run(port=8080)

