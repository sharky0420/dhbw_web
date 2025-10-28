from __future__ import annotations

import datetime as dt
import hashlib
import json
import math
import os
import secrets
import sqlite3
from dataclasses import dataclass
import hashlib
from urllib import request, parse
from urllib.request import Request
import urllib.request
from http.client import HTTPResponse

import utility
import database_util

from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)


@dataclass
class User:
    id: int
    username: str
    password: str
    name: str
    balance: float = 0.0
    cards: list[dict[str, str]] | None = None
    public_key: str | None = None
    private_key: str | None = None
    initial_balance: float = 0.0

    @staticmethod
    def from_row(row: sqlite3.Row) -> "User":
        cards_raw = row["cards"] if "cards" in row.keys() else None
        cards = json.loads(cards_raw) if cards_raw else []
        public_key = row["public_key"] if "public_key" in row.keys() else None
        private_key = row["private_key"] if "private_key" in row.keys() else None
        if "initial_balance" in row.keys() and row["initial_balance"] is not None:
            initial_balance = row["initial_balance"]
        else:
            initial_balance = row["balance"]
        return User(
            id=row["id"],
            username=row["username"],
            password=row["password"],
            name=row["name"],
            balance=row["balance"],
            cards=cards,
            public_key=public_key,
            private_key=private_key,
            initial_balance=initial_balance,
        )


DATABASE_PATH = os.environ.get("BANK_DB_PATH", os.path.join(os.path.dirname(__file__), "bank.db"))
OTHER_BANK_IPS: list[str] = []




app = Flask(__name__)
app.secret_key = os.environ.get("BANK_SECRET_KEY", "retro-bank-secret-key")


def is_authenticated() -> bool:
    return session.get("logged_in", False) and session.get("user_id") is not None


def require_authentication():
    if not is_authenticated():
        flash("Bitte melden Sie sich zuerst an.", "error")
        return redirect(url_for("login"))
    return None


def create_two_factor_code() -> str:
    code = f"{secrets.randbelow(1_000_000):06d}"
    session["two_factor_code"] = code
    session["two_factor_created"] = dt.datetime.utcnow().isoformat()
    return code


def _normalize_code(code: str) -> str:
    """Normalize a user supplied 2FA code to digits only."""

    return "".join(ch for ch in code if ch.isdigit())


def validate_two_factor_code(code: str) -> bool:
    code = _normalize_code(code)

    stored_code = session.get("two_factor_code")
    created_raw = session.get("two_factor_created")
    if not stored_code or not created_raw:
        return False

    created_at = dt.datetime.fromisoformat(created_raw)
    if dt.datetime.utcnow() - created_at > dt.timedelta(minutes=5):
        return False
    return stored_code == code


@app.route("/")
def index():
    if is_authenticated():
        return redirect(url_for("account"))
    return redirect(url_for("login"))

@app.route("/dashboard")
def dashboard():
    with database_util.get_db() as db:
        cursor = db.execute("SELECT * FROM users ")
        users : list[utility.User] = []
        for row in cursor.fetchall():
            users.append(utility.User.from_row(row))

        feedback_cursor = db.execute("SELECT * FROM feedback")
        feedbacks = feedback_cursor.fetchall()

        return render_template("dashboard.html", users=users, feedbacks=feedbacks)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = database_util.match_user(username, password)
        if user:
            session.clear()
            session["pending_user_id"] = user.id
            code = create_two_factor_code()
            flash(
                "2-Faktor-Code generiert. Nutzen Sie Ihren Authenticator oder das Demo-Pad unten.",
                "info",
            )
            session["demo_code"] = code  # Demo für In-App Anzeige
            return redirect(url_for("two_factor"))

        flash("Ungültiger Login. Bitte erneut versuchen.", "error")

    if is_authenticated():
        return redirect(url_for("account"))

    return render_template("login.html")


@app.route("/two-factor", methods=["GET", "POST"])
def two_factor():
    pending_user_id = session.get("pending_user_id")
    if not pending_user_id:
        flash("Bitte melden Sie sich erneut an.", "error")
        return redirect(url_for("login"))

    if request.method == "POST":
        code = request.form.get("code", "")
        normalized_code = _normalize_code(code)
        if len(normalized_code) != 6:
            flash("Bitte geben Sie einen gültigen 6-stelligen Code ein.", "error")
            return render_template("two_factor.html", demo_code=session.get("demo_code"))
        if validate_two_factor_code(normalized_code):
            session.pop("two_factor_code", None)
            session.pop("two_factor_created", None)
            session.pop("demo_code", None)
            session["user_id"] = pending_user_id
            session["logged_in"] = True
            flash("Erfolgreich angemeldet!", "success")
            return redirect(url_for("account"))

        flash("Ungültiger oder abgelaufener Code.", "error")

    return render_template("two_factor.html", demo_code=session.get("demo_code"))


@app.route("/account")
def account():
    if not is_authenticated():
        flash("Bitte melden Sie sich zuerst an.", "error")
        return redirect(url_for("login"))

    user = database_util.load_user(session["user_id"])
    if not user:
        flash("Nutzer konnte nicht geladen werden.", "error")
        session.clear()
        return redirect(url_for("login"))

    rates = utility.get_exchange_rates()
    converted_balances = [
        {
            "code": code,
            "name": data["name"],
            "value": round(user.balance * data["per_usd"], 2),
            "symbol": data["symbol"],
            "rate": data["per_usd"],
        }
        for code, data in rates.items()
    ]

    feedback_count: int = database_util.get_user_feedback_count(user)
    appointment_count: int = database_util.get_user_appointment_count(user)

    raw_other_accounts = database_util.get_other_basic_user_data(user)

    raw_transactions: list[utility.Transaction] = database_util.get_user_transactions(user)

    other_accounts = [dict(row) for row in raw_other_accounts]
    processed_transactions = []
    for transaction in raw_transactions:


        counterparty_user_public_key: str = ""
        if transaction.is_user_sender(user):
            direction = "outgoing"
            opposing_user_public_key = transaction.receiver_public_key
        else:
            direction = "incoming"
            opposing_user_public_key = transaction.sender_public_key

        counterparty_user: utility.User | None = database_util.load_user_by_public_key(opposing_user_public_key)

        counterparty_name = counterparty_user.name if counterparty_user else "Unbekannt"

        processed_transactions.append(
            {
                "id": transaction.id,
                "amount": transaction.amount,
                "created_at": transaction.created_at,
                "direction": direction,
                "counterparty_name": counterparty_name,
                "counterparty_public_key": counterparty_user_public_key,
            }
        )

    return render_template(
        "account.html",
        balance=user.balance,
        username=user.name,
        base_currency="USD",
        conversions=sorted(converted_balances, key=lambda entry: entry["code"]),
        cards=user.cards or [],
        feedback_count=feedback_count,
        appointment_count=appointment_count,
        other_accounts=other_accounts,
        transactions=processed_transactions,
    )


@app.route("/logout")
def logout():
    session.clear()
    flash("Sie wurden abgemeldet.", "info")
    return redirect(url_for("login"))


@app.route("/api/balance")
def api_balance():
    if not is_authenticated():
        return jsonify({"error": "Unauthorized"}), 401

    user = database_util.load_user(session["user_id"])
    if not user:
        return jsonify({"error": "User not found"}), 404

    rates = utility.get_exchange_rates()
    conversions = {
        code: {
            "name": data["name"],
            "rate": data["per_usd"],
            "value": round(user.balance * data["per_usd"], 2),
            "symbol": data["symbol"],
        }
        for code, data in rates.items()
    }
    return jsonify(
        {
            "balance": user.balance,
            "currency": "USD",
            "conversions": conversions,
            "timestamp": dt.datetime.utcnow().isoformat(),
        }
    )


@app.route("/api/feedback", methods=["POST"])
def api_feedback():
    if not is_authenticated():
        return jsonify({"error": "Unauthorized"}), 401

    message = request.json.get("message", "").strip()
    if not message:
        return jsonify({"error": "Leere Nachricht"}), 400

    with database_util.get_db() as db:
        db.execute(
            "INSERT INTO feedback (user_id, message, created_at) VALUES (?, ?, ?)",
            (session["user_id"], message, dt.datetime.utcnow().isoformat()),
        )
    return jsonify({"status": "ok"}), 201


@app.route("/api/transfer", methods=["POST"])
def api_transfer():
    if not is_authenticated():
        return jsonify({"error": "Unauthorized"}), 401

    payload = request.json or {}
    recipient_public_key: str = payload.get("recipient", "").strip()
    amount_raw = payload.get("amount")

    try:
        amount = float(amount_raw)
    except (TypeError, ValueError):
        return jsonify({"error": "Ungültiger Betrag"}), 400

    if math.isnan(amount) or math.isinf(amount) or amount <= 0:
        return jsonify({"error": "Bitte geben Sie einen positiven Betrag ein."}), 400

    if not recipient_public_key:
        return jsonify({"error": "Bitte wählen Sie ein Zielkonto."}), 400

    sender: utility.User = database_util.load_user(session["user_id"])
    if not sender:
        return jsonify({"error": "Absenderkonto wurde nicht gefunden."}), 404

    receiver: utility.User | None = database_util.load_user_by_public_key(recipient_public_key)


    if sender.public_key == recipient_public_key:
        return jsonify({"error": "Überweisungen an das eigene Konto sind nicht erlaubt."}), 400

    if sender.balance < amount:
        return jsonify({"error": "Unzureichendes Guthaben."}), 400


    new_sender_balance = sender.balance - amount

    with database_util.get_db() as db:
        db.execute(
            "UPDATE users SET balance = ? WHERE id = ?",
            (new_sender_balance, sender.id)
        )

        if receiver:
            db.execute(
                "UPDATE users SET balance = ? WHERE id = ?",
                (receiver.balance + amount, receiver.id)
            )

    timestamp = dt.datetime.now()
    database_util.add_transaction(sender.public_key, recipient_public_key, amount, timestamp)

    synchronize_with_other_clients(sender.public_key, recipient_public_key, amount)

    return jsonify(
        {
            "status": "ok",
            "balance": new_sender_balance,
            "recipient": {
                "name": receiver.name if receiver else "Unknwon",
                "username": recipient_public_key,
            },
            "amount": amount,
            "timestamp": timestamp.isoformat()
        }
    )


@app.route("/api/transactions")
def api_transactions():
    if not is_authenticated():
        return jsonify({"error": "Unauthorized"}), 401

    user = database_util.load_user(session["user_id"])
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    raw_transactions: list[utility.Transaction] = database_util.get_user_transactions(user)

    processed_transactions = []
    for transaction in raw_transactions:


        counterparty_user_public_key: str = ""
        if transaction.is_user_sender(user):
            direction = "outgoing"
            opposing_user_public_key = transaction.receiver_public_key
        else:
            direction = "incoming"
            opposing_user_public_key = transaction.sender_public_key

        counterparty_user: utility.User | None = database_util.load_user_by_public_key(opposing_user_public_key)

        counterparty_name = counterparty_user.name if counterparty_user else "Unbekannt"

        processed_transactions.append(
            {
                "id": transaction.id,
                "amount": transaction.amount,
                "created_at": transaction.created_at,
                "direction": direction,
                "counterparty_name": counterparty_name,
                "counterparty_public_key": counterparty_user_public_key,
            }
        )


    return jsonify({"transactions": processed_transactions})


@app.route("/api/appointments", methods=["GET", "POST"])
def api_appointments():
    if not is_authenticated():
        return jsonify({"error": "Unauthorized"}), 401

    if request.method == "POST":
        data = request.json or {}
        date_value = data.get("date")
        time_value = data.get("time")
        if not date_value or not time_value:
            return jsonify({"error": "Datum und Zeit erforderlich"}), 400

        with database_util.get_db() as db:
            db.execute(
                "INSERT INTO appointments (user_id, appointment_date, appointment_time, created_at) VALUES (?, ?, ?, ?)",
                (
                    session["user_id"],
                    date_value,
                    time_value,
                    dt.datetime.utcnow().isoformat(),
                ),
            )
        return jsonify({"status": "ok"}), 201

    with database_util.get_db() as db:
        rows = db.execute(
            "SELECT appointment_date, appointment_time, created_at FROM appointments WHERE user_id = ? ORDER BY created_at DESC LIMIT 10",
            (session["user_id"],),
        ).fetchall()
    appointments = [dict(row) for row in rows]
    return jsonify({"appointments": appointments})


@app.route("/api/chat", methods=["GET", "POST"])
def api_chat():
    if not is_authenticated():
        return jsonify({"error": "Unauthorized"}), 401

    if request.method == "POST":
        message = request.json.get("message", "").strip()
        if not message:
            return jsonify({"error": "Leere Nachricht"}), 400

        timestamp = dt.datetime.utcnow().isoformat()
        with database_util.get_db() as db:
            db.execute(
                "INSERT INTO chat_messages (user_id, sender, message, created_at) VALUES (?, ?, ?, ?)",
                (session["user_id"], "user", message, timestamp),
            )

        bot_reply = (
            "Danke für Ihre Nachricht! Ein Berater meldet sich in Kürze."
            if "termin" in message.lower()
            else "Wir haben Ihr Anliegen erhalten und kümmern uns darum."
        )
        with database_util.get_db() as db:
            db.execute(
                "INSERT INTO chat_messages (user_id, sender, message, created_at) VALUES (?, ?, ?, ?)",
                (session["user_id"], "assistant", bot_reply, dt.datetime.utcnow().isoformat()),
            )
        return jsonify({"status": "ok"}), 201

    with database_util.get_db() as db:
        rows = db.execute(
            "SELECT sender, message, created_at FROM chat_messages WHERE user_id = ? ORDER BY created_at DESC LIMIT 20",
            (session["user_id"],),
        ).fetchall()
    messages = [dict(row) for row in rows]
    return jsonify({"messages": list(reversed(messages))})



@app.route("/tk/<sender>/<receiver>/<amount>/<signature>", methods= ["POST"])
def process_incoming_transaction():
    sender: str = request.view_args.get("sender", None)
    receiver: str = request.view_args.get("receiver", None)
    amount_as_string: str = request.view_args.get("amount", None)
    received_signature: str = request.view_args.get("signature", None)

    if sender is None or receiver is None or amount_as_string is None or received_signature is None:
        return jsonify({"error": "Missing information"}), 400
    amount: float = 0.0
    try:
        amount = float(amount_as_string)
    except:
        return jsonify({"error": "Invalid amount format"}), 400

    if amount <= 0:
        return jsonify({"error": "Amount must be positive"}), 400


    calculated_signature: str = build_signature(sender, receiver, amount_as_string)
    if received_signature != calculated_signature:
        return jsonify({"error": "Signature does not match content!"}), 400

    return jsonify({"valid": "Signature is valid!!!"}), 200

def build_signature(sender, receiver, amount) -> str:
    signature_base_string: str = f"{sender};{receiver};{amount}"
    hash = hashlib.md5(signature_base_string.encode())

    return hash.hexdigest()

def synchronize_with_other_clients(sender_public_key, receiver_public_key, amount):
    calculated_signature: str = build_signature(sender_public_key, receiver_public_key, str(amount))

    url_path: str = f"/tx/{sender_public_key}/{receiver_public_key}/{amount}/{calculated_signature}"

    for bank_ip in OTHER_BANK_IPS:
        full_url: str = f"http://{bank_ip}{url_path}"

        req = Request(full_url, b"", method="POST")
        print("#" * 10)
        print("New Ledger:")
        try:
            resp:  HTTPResponse = urllib.request.urlopen(req)
            status_code: int = resp.status

            if status_code == 200:
                print(f"VALID RESPONSE to {bank_ip}")
            else:
                print(f"INVALID RESPONSE to {bank_ip}, {status_code}, {resp.read()}")
            resp.close()

        except Exception as e:
            print(f"COULD NOT COMMIT TO {bank_ip}", e)




if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port="80")
