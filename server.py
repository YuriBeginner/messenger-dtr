from flask import Flask, request

app = Flask(__name__)

VERIFY_TOKEN = "ojt_dtr_token"

@app.route("/", methods=["GET"])
def home():
    return "OJT DTR Bot is running!"

@app.route("/webhook", methods=["GET"])
def verify():
    token = request.args.get("hub.verify_token")
    challenge = request.args.get("hub.challenge")

    if token == VERIFY_TOKEN:
        return challenge
    return "Verification failed"

@app.route("/webhook", methods=["POST"])
def webhook():
    data = request.json
    print("Received message:", data)
    return "ok", 200
