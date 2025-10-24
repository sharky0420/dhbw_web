from __future__ import annotations

import datetime as dt
import json
import math
import os
import secrets
import sqlite3
from dataclasses import dataclass

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

    @staticmethod
    def from_row(row: sqlite3.Row) -> "User":
        cards_raw = row["cards"] if "cards" in row.keys() else None
        cards = json.loads(cards_raw) if cards_raw else []
        return User(
            id=row["id"],
            username=row["username"],
            password=row["password"],
            name=row["name"],
            balance=row["balance"],
            cards=cards,
        )


DATABASE_PATH = os.environ.get("BANK_DB_PATH", os.path.join(os.path.dirname(__file__), "bank.db"))

app = Flask(__name__)
app.secret_key = os.environ.get("BANK_SECRET_KEY", "retro-bank-secret-key")


def get_db() -> sqlite3.Connection:
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db() -> None:
    with get_db() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                name TEXT NOT NULL,
                balance REAL NOT NULL DEFAULT 0.0,
                cards TEXT
            );

            CREATE TABLE IF NOT EXISTS feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                message TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS appointments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                appointment_date TEXT NOT NULL,
                appointment_time TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS chat_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                sender TEXT NOT NULL,
                message TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER NOT NULL,
                recipient_id INTEGER NOT NULL,
                amount REAL NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (sender_id) REFERENCES users(id),
                FOREIGN KEY (recipient_id) REFERENCES users(id)
            );
            """
        )

        cursor = db.execute("SELECT COUNT(*) FROM users")
        if cursor.fetchone()[0] == 0:
            demo_cards = json.dumps(
                [
                    {"type": "Debit", "masked": "**** **** **** 1234", "status": "Aktiv"},
                    {"type": "Kredit", "masked": "**** **** **** 9876", "status": "Aktiv"},
                ]
            )
            db.executemany(
                "INSERT INTO users (username, password, name, balance, cards) VALUES (?, ?, ?, ?, ?)",
                [
                    ("test", "test", "Nutzer 1", 1337.42, demo_cards),
                    ("user", "user", "Hallo Welt", 2.12, demo_cards),
                    ("root", "root", "MEnsch 1", 1.42, demo_cards),
                ],
            )


init_db()


# Wechselkurse (Basisdaten, dynamisch angepasst)
CURRENCY_RATES_2000 = {
    "DEM": {"name": "Deutsche Mark", "per_usd": 2.04, "symbol": "DM"},
    "FRF": {"name": "Französischer Franc", "per_usd": 6.75, "symbol": "F"},
    "ITL": {"name": "Italienische Lira", "per_usd": 2031.00, "symbol": "₤"},
    "ESP": {"name": "Spanische Peseta", "per_usd": 170.00, "symbol": "₧"},
    "ATS": {"name": "Österreichischer Schilling", "per_usd": 14.20, "symbol": "S"},
    "NLG": {"name": "Niederländischer Gulden", "per_usd": 2.18, "symbol": "ƒ"},
    "BEF": {"name": "Belgischer Franc", "per_usd": 41.00, "symbol": "FB"},
}


def get_exchange_rates() -> dict[str, dict[str, float | str]]:
    """Erzeuge dynamische Wechselkurse als Echtzeit-Demo."""

    now = dt.datetime.utcnow()
    dynamic_rates: dict[str, dict[str, float | str]] = {}
    for idx, (code, data) in enumerate(CURRENCY_RATES_2000.items(), start=1):
        oscillation = 1 + math.sin(now.timestamp() / (180 + idx * 12)) * 0.05
        value = round(data["per_usd"] * oscillation, 4)
        dynamic_rates[code] = {
            "name": data["name"],
            "per_usd": value,
            "symbol": data["symbol"],
        }
    return dynamic_rates


def match_user(username: str, password: str) -> User | None:
    with get_db() as db:
        cursor = db.execute(
            "SELECT * FROM users WHERE username = ? AND password = ?",
            (username, password),
        )
        row = cursor.fetchone()
        if not row:
            return None
        return User.from_row(row)


def load_user(user_id: int) -> User | None:
    with get_db() as db:
        cursor = db.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        row = cursor.fetchone()
        if not row:
            return None
        return User.from_row(row)


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
def dashbaord():
    with get_db() as db:
        cursor = db.execute("SELECT * FROM users ")
        users : list[User] = []
        for row in cursor.fetchall():
            users.append(User.from_row(row))
        
        feedback_cursor = db.execute("SELECT * FROM feedback")
        feedbacks = feedback_cursor.fetchall()

        return render_template("dashboard.html", users=users, feedbacks=feedbacks)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = match_user(username, password)
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

    user = load_user(session["user_id"])
    if not user:
        flash("Nutzer konnte nicht geladen werden.", "error")
        session.clear()
        return redirect(url_for("login"))

    rates = get_exchange_rates()
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

    with get_db() as db:
        feedback_count = (
            db.execute("SELECT COUNT(*) FROM feedback WHERE user_id = ?", (user.id,))
            .fetchone()[0]
        )
        appointment_count = (
            db.execute("SELECT COUNT(*) FROM appointments WHERE user_id = ?", (user.id,))
            .fetchone()[0]
        )
        account_rows = db.execute(
            "SELECT id, username, name FROM users WHERE id != ? ORDER BY name",
            (user.id,),
        ).fetchall()
        transaction_rows = db.execute(
            """
            SELECT
                t.id,
                t.sender_id,
                t.recipient_id,
                t.amount,
                t.created_at,
                sender.name AS sender_name,
                recipient.name AS recipient_name,
                sender.username AS sender_username,
                recipient.username AS recipient_username
            FROM transactions AS t
            LEFT JOIN users AS sender ON sender.id = t.sender_id
            LEFT JOIN users AS recipient ON recipient.id = t.recipient_id
            WHERE t.sender_id = ? OR t.recipient_id = ?
            ORDER BY t.created_at DESC
            LIMIT 10
            """,
            (user.id, user.id),
        ).fetchall()

    other_accounts = [dict(row) for row in account_rows]
    transactions = []
    for row in transaction_rows:
        direction = "outgoing" if row["sender_id"] == user.id else "incoming"
        counterparty_name = (
            row["recipient_name"] if direction == "outgoing" else row["sender_name"]
        )
        counterparty_username = (
            row["recipient_username"]
            if direction == "outgoing"
            else row["sender_username"]
        )
        transactions.append(
            {
                "id": row["id"],
                "amount": row["amount"],
                "created_at": row["created_at"],
                "direction": direction,
                "counterparty_name": counterparty_name,
                "counterparty_username": counterparty_username,
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
        transactions=transactions,
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

    user = load_user(session["user_id"])
    if not user:
        return jsonify({"error": "User not found"}), 404

    rates = get_exchange_rates()
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

    with get_db() as db:
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
    recipient_username = payload.get("recipient", "").strip()
    amount_raw = payload.get("amount")

    try:
        amount = float(amount_raw)
    except (TypeError, ValueError):
        return jsonify({"error": "Ungültiger Betrag"}), 400

    if math.isnan(amount) or math.isinf(amount) or amount <= 0:
        return jsonify({"error": "Bitte geben Sie einen positiven Betrag ein."}), 400

    if not recipient_username:
        return jsonify({"error": "Bitte wählen Sie ein Zielkonto."}), 400

    user_id = session["user_id"]

    with get_db() as db:
        sender_row = db.execute(
            "SELECT id, balance FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
        if not sender_row:
            return jsonify({"error": "Absenderkonto wurde nicht gefunden."}), 404

        recipient_row = db.execute(
            "SELECT id, balance, name, username FROM users WHERE username = ?",
            (recipient_username,),
        ).fetchone()

        if not recipient_row:
            return jsonify({"error": "Zielkonto wurde nicht gefunden."}), 404

        if recipient_row["id"] == user_id:
            return jsonify({"error": "Überweisungen an das eigene Konto sind nicht erlaubt."}), 400

        sender_balance = float(sender_row["balance"])
        if sender_balance < amount:
            return jsonify({"error": "Unzureichendes Guthaben."}), 400

        recipient_balance = float(recipient_row["balance"])

        new_sender_balance = round(sender_balance - amount, 2)
        new_recipient_balance = round(recipient_balance + amount, 2)
        timestamp = dt.datetime.utcnow().isoformat()

        db.execute(
            "UPDATE users SET balance = ? WHERE id = ?",
            (new_sender_balance, user_id),
        )
        db.execute(
            "UPDATE users SET balance = ? WHERE id = ?",
            (new_recipient_balance, recipient_row["id"]),
        )
        db.execute(
            "INSERT INTO transactions (sender_id, recipient_id, amount, created_at) VALUES (?, ?, ?, ?)",
            (user_id, recipient_row["id"], amount, timestamp),
        )

    return jsonify(
        {
            "status": "ok",
            "balance": new_sender_balance,
            "recipient": {
                "name": recipient_row["name"],
                "username": recipient_row["username"],
            },
            "amount": amount,
            "timestamp": timestamp,
        }
    )


@app.route("/api/transactions")
def api_transactions():
    if not is_authenticated():
        return jsonify({"error": "Unauthorized"}), 401

    user_id = session["user_id"]

    with get_db() as db:
        rows = db.execute(
            """
            SELECT
                t.id,
                t.sender_id,
                t.recipient_id,
                t.amount,
                t.created_at,
                sender.name AS sender_name,
                recipient.name AS recipient_name,
                sender.username AS sender_username,
                recipient.username AS recipient_username
            FROM transactions AS t
            LEFT JOIN users AS sender ON sender.id = t.sender_id
            LEFT JOIN users AS recipient ON recipient.id = t.recipient_id
            WHERE t.sender_id = ? OR t.recipient_id = ?
            ORDER BY t.created_at DESC
            LIMIT 20
            """,
            (user_id, user_id),
        ).fetchall()

    transactions: list[dict[str, object]] = []
    for row in rows:
        direction = "outgoing" if row["sender_id"] == user_id else "incoming"
        counterparty_name = (
            row["recipient_name"] if direction == "outgoing" else row["sender_name"]
        )
        counterparty_username = (
            row["recipient_username"]
            if direction == "outgoing"
            else row["sender_username"]
        )
        transactions.append(
            {
                "id": row["id"],
                "amount": row["amount"],
                "created_at": row["created_at"],
                "direction": direction,
                "counterparty_name": counterparty_name,
                "counterparty_username": counterparty_username,
            }
        )

    return jsonify({"transactions": transactions})


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

        with get_db() as db:
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

    with get_db() as db:
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
        with get_db() as db:
            db.execute(
                "INSERT INTO chat_messages (user_id, sender, message, created_at) VALUES (?, ?, ?, ?)",
                (session["user_id"], "user", message, timestamp),
            )

        bot_reply = (
            "Danke für Ihre Nachricht! Ein Berater meldet sich in Kürze."
            if "termin" in message.lower()
            else "Wir haben Ihr Anliegen erhalten und kümmern uns darum."
        )
        with get_db() as db:
            db.execute(
                "INSERT INTO chat_messages (user_id, sender, message, created_at) VALUES (?, ?, ?, ?)",
                (session["user_id"], "assistant", bot_reply, dt.datetime.utcnow().isoformat()),
            )
        return jsonify({"status": "ok"}), 201

    with get_db() as db:
        rows = db.execute(
            "SELECT sender, message, created_at FROM chat_messages WHERE user_id = ? ORDER BY created_at DESC LIMIT 20",
            (session["user_id"],),
        ).fetchall()
    messages = [dict(row) for row in rows]
    return jsonify({"messages": list(reversed(messages))})


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port="80")
