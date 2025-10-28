import json
import os
import sqlite3

import util

DATABASE_PATH = os.environ.get("BANK_DB_PATH", os.path.join(os.path.dirname(__file__), "bank.db"))

def get_db() -> sqlite3.Connection:
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def setup_database_tables() -> None:
    with get_db() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                name TEXT NOT NULL,
                balance REAL NOT NULL DEFAULT 0.0,
                public_key TEXT NOT NULL UNIQUE,
                private_key TEXT NOT NULL,
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
                sender_public_key TEXT NOT NULL,
                receiver_public_key TEXT NOT NULL,
                amount REAL NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )


def insert_users_if_not_exist() -> None:
    with get_db() as db:
        cursor = db.execute("SELECT COUNT(*) FROM users")
        if cursor.fetchone()[0] == 0:
            demo_cards = json.dumps(
                [
                    {"type": "Debit", "masked": "**** **** **** 1234", "status": "Aktiv"},
                    {"type": "Kredit", "masked": "**** **** **** 9876", "status": "Aktiv"},
                ]
            )
            db.executemany(
                "INSERT INTO users (username, password, name, balance, public_key, private_key, cards) VALUES (?, ?, ?, ?, ?, ?, ?)",
                [
                    ("test", "test", "Nutzer 1", 1337.42, "PUB_1-1234", "PRV_1-4321", demo_cards),
                    ("user", "user", "Hallo Welt", 2.12, "PUB-2-5678", "PRV_2-8765", demo_cards),
                    ("root", "root", "MEnsch 1", 1.42, "PUB_3-9012", "PRV_3-2109", demo_cards),
                ],
            )


def match_user(username: str, password: str) -> util.User | None:
    with get_db() as db:
        cursor = db.execute(
            "SELECT * FROM users WHERE username = ? AND password = ?",
            (username, password),
        )
        row = cursor.fetchone()
        if not row:
            return None
        return util.User.from_row(row)


def load_user(user_id: int) -> util.User | None:
    with get_db() as db:
        cursor = db.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        row = cursor.fetchone()
        if not row:
            return None
        return util.User.from_row(row)


def load_user_by_username(username: str) -> util.User | None:
    with get_db() as db:
        row = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if not row:
            return None
        return util.User.from_row(row)


def load_user_by_public_key(public_key: str) -> util.User | None:
    with get_db() as db:
        row = db.execute("SELECT * FROM users WHERE public_key = ?", (public_key,)).fetchone()
        if not row:
            return None
        return util.User.from_row(row)


def get_user_feedback_count(user: util.User) -> int:
    with get_db() as db:
        feedback_count = (
            db.execute("SELECT COUNT(*) FROM feedback WHERE user_id = ?", (user.id,))
            .fetchone()[0]
        )
        return feedback_count


def get_user_appointment_count(user: util.User) -> int:
    with get_db() as db:
        feedback_count = (
            db.execute("SELECT COUNT(*) FROM appointments WHERE user_id = ?", (user.id,))
            .fetchone()[0]
        )
        return feedback_count


def get_user_transactions(user: util.User) -> list[util.Transaction]:
    with get_db() as db:
        transaction_rows = db.execute(
            """
            SELECT *
            FROM transactions
            WHERE sender_public_key = ? OR receiver_public_key = ?
            ORDER BY created_at DESC
            LIMIT 10
            """,
            (user.public_key, user.public_key),
        ).fetchall()

        transactions: list[util.Transaction] = []

        for row in transaction_rows:
            transactions.append(util.Transaction.from_row(row))
        return transactions


def get_other_basic_user_data(user: util.User) -> list[dict[str, str]]:
    with get_db() as db:
        account_rows = db.execute(
            "SELECT id, username, name, public_key FROM users WHERE id != ? ORDER BY name",
            (user.id,),
        ).fetchall()
        return account_rows


def add_transaction(sender_public_key, receiver_public_key, amount, created_at: str = "") -> None:
    with get_db() as db:
        db.execute(
            "INSERT INTO transactions (sender_public_key, receiver_public_key, amount, created_at) VALUES (?, ?, ?, ?)",
            (sender_public_key, receiver_public_key, amount, created_at),
        )


setup_database_tables()
insert_users_if_not_exist()
