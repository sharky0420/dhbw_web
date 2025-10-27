from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import math
import os
import secrets
import sqlite3
from dataclasses import dataclass
from typing import Sequence

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


@dataclass
class LedgerEntry:
    """Immutable representation of a blockchain transaction entry."""

    id: str
    sender_public_key: str
    receiver_public_key: str
    signature: str
    amount: float
    payload_hash: str = None
    previous_hash: str = None
    created_at: str = None


DATABASE_PATH = os.environ.get("BANK_DB_PATH", os.path.join(os.path.dirname(__file__), "bank.db"))


def _hash_private_key(private_key: str) -> str:
    """Derive a deterministic public key from a private key using SHA-256."""

    return hashlib.sha256(private_key.encode("utf-8")).hexdigest()


def generate_key_pair() -> tuple[str, str]:
    """Generate a new key pair suitable for signing demo transactions."""

    private_key = secrets.token_hex(32)
    public_key = _hash_private_key(private_key)
    return public_key, private_key


def get_peer_database_paths() -> list[str]:
    """Return configured peer database paths.

    Peers can be supplied either as a JSON array or a comma separated string.
    """

    raw_value = os.environ.get("BANK_PEER_DATABASES", "").strip()
    if not raw_value:
        return []

    try:
        parsed = json.loads(raw_value)
    except json.JSONDecodeError:
        parsed = [segment.strip() for segment in raw_value.split(",") if segment.strip()]
    else:
        if isinstance(parsed, list):
            parsed = [str(item) for item in parsed if str(item).strip()]
        else:
            parsed = []
    return [path for path in parsed if path]


class LedgerIntegrityError(RuntimeError):
    """Raised when the blockchain ledger cannot guarantee integrity."""


def ensure_user_schema(connection: sqlite3.Connection) -> None:
    """Ensure that user-related cryptographic columns exist."""

    connection.row_factory = sqlite3.Row
    columns = {
        row["name"]
        for row in connection.execute("PRAGMA table_info(users)").fetchall()
    }
    if "public_key" not in columns:
        connection.execute("ALTER TABLE users ADD COLUMN public_key TEXT")
    if "private_key" not in columns:
        connection.execute("ALTER TABLE users ADD COLUMN private_key TEXT")
    if "initial_balance" not in columns:
        connection.execute("ALTER TABLE users ADD COLUMN initial_balance REAL")
    connection.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_public_key ON users(public_key)"
    )


def ensure_user_keys(connection: sqlite3.Connection) -> None:
    """Populate missing key pairs and baseline balances for all users."""

    ensure_user_schema(connection)
    cursor = connection.execute(
        "SELECT id, balance, initial_balance, public_key, private_key FROM users"
    )
    for row in cursor.fetchall():
        updates: list[str] = []
        params: list[object] = []
        public_key = row["public_key"]
        private_key = row["private_key"]
        if not public_key or not private_key:
            public_key, private_key = generate_key_pair()
            updates.extend(["public_key = ?", "private_key = ?"])
            params.extend([public_key, private_key])
        if row["initial_balance"] is None:
            updates.append("initial_balance = ?")
            params.append(row["balance"])
        if updates:
            params.append(row["id"])
            connection.execute(
                f"UPDATE users SET {', '.join(updates)} WHERE id = ?",
                params,
            )


class BlockchainLedger:
    """Simple blockchain-inspired ledger to synchronize transactions across banks."""

    def __init__(self, database_path: str, peer_paths: Sequence[str] | None = None) -> None:
        self.database_path = database_path
        self.peer_paths = [path for path in (peer_paths or []) if path and path != database_path]
        self._initialize_local_state()

    @staticmethod
    def _connect(path: str) -> sqlite3.Connection:
        connection = sqlite3.connect(path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize_local_state(self) -> None:
        with self._connect(self.database_path) as connection:
            self._ensure_tables(connection)
            ensure_user_keys(connection)

    @staticmethod
    def _ensure_tables(connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS blockchain_transactions (
                id TEXT PRIMARY KEY,
                sender_public_key TEXT NOT NULL,
                receiver_public_key TEXT NOT NULL,
                signature TEXT NOT NULL,
                amount REAL NOT NULL,
                -- payload_hash TEXT NOT NULL,
                -- previous_hash TEXT,
                -- created_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_blockchain_sender ON blockchain_transactions(sender_public_key)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_blockchain_receiver ON blockchain_transactions(receiver_public_key)"
        )

    @staticmethod
    def _build_message(sender_public_key: str, receiver_public_key: str, amount: float) -> str:
        return f"{sender_public_key}:{receiver_public_key}:{amount:.2f}"

    @staticmethod
    def _sign_message(private_key: str, message: str) -> str:
        key_bytes = bytes.fromhex(private_key)
        digest = hmac.new(key_bytes, message.encode("utf-8"), hashlib.sha256)
        return digest.hexdigest()

    @staticmethod
    def _calculate_payload_hash(
        entry_id: str,
        previous_hash: str | None,
        sender_public_key: str,
        receiver_public_key: str,
        amount: float,
        signature: str,
        created_at: str,
    ) -> str:
        payload = "|".join(
            [
                entry_id,
                previous_hash or "",
                sender_public_key,
                receiver_public_key,
                f"{amount:.2f}",
                signature,
                created_at,
            ]
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    @staticmethod
    def _row_to_entry(row: sqlite3.Row) -> LedgerEntry:
        return LedgerEntry(
            id=row["id"],
            sender_public_key=row["sender_public_key"],
            receiver_public_key=row["receiver_public_key"],
            signature=row["signature"],
            amount=row["amount"],
            # payload_hash=row["payload_hash"],
            # previous_hash=row["previous_hash"],
            # created_at=row["created_at"],
        )

    def _get_last_payload_hash_from_connection(
        self, connection: sqlite3.Connection
    ) -> str | None:
        row = connection.execute(
            "SELECT payload_hash FROM blockchain_transactions ORDER BY created_at DESC LIMIT 1"
        ).fetchone()
        return row["payload_hash"] if row else None

    def _get_last_payload_hash(self, path: str) -> str | None:
        with self._connect(path) as connection:
            return self._get_last_payload_hash_from_connection(connection)

    def _verify_signature(
        self, connection: sqlite3.Connection, entry: LedgerEntry
    ) -> bool:
        ensure_user_keys(connection)
        row = connection.execute(
            "SELECT private_key FROM users WHERE public_key = ?",
            (entry.sender_public_key,),
        ).fetchone()
        if not row or not row["private_key"]:
            return False
        expected = self._sign_message(
            row["private_key"],
            self._build_message(entry.sender_public_key, entry.receiver_public_key, entry.amount),
        )
        return hmac.compare_digest(expected, entry.signature)

    def create_entry(self, sender: User, recipient: User, amount: float) -> LedgerEntry:
        if not sender.public_key or not sender.private_key:
            raise LedgerIntegrityError("Sender has no cryptographic identity configured.")
        if not recipient.public_key:
            raise LedgerIntegrityError("Recipient has no cryptographic identity configured.")

        previous_hash = self._get_last_payload_hash(self.database_path)
        created_at = dt.datetime.utcnow().isoformat()
        entry_id = secrets.token_hex(16)
        signature = f"{sender.public_key};{recipient.public_key};{amount:.2f}"
        payload_hash = self._calculate_payload_hash(
            entry_id,
            previous_hash,
            sender.public_key,
            recipient.public_key,
            amount,
            signature,
            created_at,
        )
        return LedgerEntry(
            id=entry_id,
            sender_public_key=sender.public_key,
            receiver_public_key=recipient.public_key,
            signature=signature,
            amount=round(amount, 2),
            # payload_hash=payload_hash,
            # previous_hash=previous_hash,
            # created_at=created_at,
        )

    def persist_entry(
        self,
        connection: sqlite3.Connection,
        entry: LedgerEntry,
        *,
        enforce_balance: bool = True,
        enforce_chain: bool = True,
        verify_signature: bool = True,
    ) -> tuple[float, float] | None:
        """Store a ledger entry and adjust account balances."""

        self._ensure_tables(connection)
        ensure_user_keys(connection)

        sender_row = connection.execute(
            "SELECT id, balance FROM users WHERE public_key = ?",
            (entry.sender_public_key,),
        ).fetchone()
        recipient_row = connection.execute(
            "SELECT id, balance FROM users WHERE public_key = ?",
            (entry.receiver_public_key,),
        ).fetchone()

        if not sender_row or not recipient_row:
            raise LedgerIntegrityError("Sender or recipient is unknown to this ledger.")

        sender_balance = float(sender_row["balance"])
        recipient_balance = float(recipient_row["balance"])

        if enforce_balance and sender_balance + 1e-9 < entry.amount:
            raise LedgerIntegrityError("Insufficient funds for ledger entry.")

        if verify_signature and not self._verify_signature(connection, entry):
            raise LedgerIntegrityError("Invalid transaction signature detected.")

        if enforce_chain:
            last_hash = self._get_last_payload_hash_from_connection(connection)
            if last_hash != entry.previous_hash:
                raise LedgerIntegrityError("Ledger chain continuity check failed.")

        try:
            connection.execute(
                """
                INSERT INTO blockchain_transactions (
                    id, sender_public_key, receiver_public_key,  signature, amount,
                    -- payload_hash, previous_hash, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entry.id,
                    entry.sender_public_key,
                    entry.receiver_public_key,
                    entry.signature,
                    entry.amount,
                    # entry.payload_hash,
                    # entry.previous_hash,
                    # entry.created_at,
                ),
            )
        except sqlite3.IntegrityError:
            return None

        new_sender_balance = round(sender_balance - entry.amount, 2)
        new_recipient_balance = round(recipient_balance + entry.amount, 2)

        connection.execute(
            "UPDATE users SET balance = ? WHERE id = ?",
            (new_sender_balance, sender_row["id"]),
        )
        connection.execute(
            "UPDATE users SET balance = ? WHERE id = ?",
            (new_recipient_balance, recipient_row["id"]),
        )
        return new_sender_balance, new_recipient_balance

    def recalculate_balances(self, connection: sqlite3.Connection) -> None:
        """Rebuild balances from the initial baseline and the blockchain."""

        ensure_user_keys(connection)
        users = connection.execute(
            "SELECT public_key, initial_balance FROM users"
        ).fetchall()
        balances = {
            row["public_key"]: float(row["initial_balance"] or 0.0) for row in users if row["public_key"]
        }
        entries = connection.execute(
            "SELECT sender_public_key, receiver_public_key, amount FROM blockchain_transactions ORDER BY created_at"
        ).fetchall()
        for row in entries:
            sender_key = row["sender_public_key"]
            receiver_key = row["receiver_public_key"]
            amount = float(row["amount"])
            if sender_key in balances:
                balances[sender_key] = round(balances[sender_key] - amount, 2)
            if receiver_key in balances:
                balances[receiver_key] = round(balances[receiver_key] + amount, 2)
        for public_key, balance in balances.items():
            connection.execute(
                "UPDATE users SET balance = ? WHERE public_key = ?",
                (balance, public_key),
            )

    def propagate_entry(self, entry: LedgerEntry) -> None:
        """Replicate an entry to all known peer databases."""

        for peer_path in self.peer_paths:
            try:
                self._apply_to_peer(peer_path, entry)
            except sqlite3.Error:
                continue
            except LedgerIntegrityError:
                try:
                    self._heal_peer(peer_path)
                    self._apply_to_peer(peer_path, entry)
                except Exception:
                    continue

    def _apply_to_peer(self, peer_path: str, entry: LedgerEntry) -> None:
        with self._connect(peer_path) as connection:
            self._ensure_tables(connection)
            ensure_user_keys(connection)
            last_hash = self._get_last_payload_hash_from_connection(connection)
            if last_hash:
                if last_hash != entry.previous_hash:
                    raise LedgerIntegrityError("Peer ledger out of sync.")
                enforce_chain = True
            else:
                if entry.previous_hash:
                    raise LedgerIntegrityError("Peer ledger missing historical blocks.")
                enforce_chain = False
            self.persist_entry(
                connection,
                entry,
                enforce_balance=False,
                enforce_chain=enforce_chain,
                verify_signature=True,
            )

    def _heal_peer(self, peer_path: str) -> None:
        with self._connect(peer_path) as peer_connection, self._connect(
            self.database_path
        ) as local_connection:
            self._ensure_tables(peer_connection)
            ensure_user_keys(peer_connection)
            peer_connection.execute(
                "UPDATE users SET balance = COALESCE(initial_balance, balance)"
            )
            peer_connection.execute("DELETE FROM blockchain_transactions")
            entries = local_connection.execute(
                "SELECT * FROM blockchain_transactions ORDER BY created_at"
            ).fetchall()
            for row in entries:
                entry = self._row_to_entry(row)
                try:
                    self.persist_entry(
                        peer_connection,
                        entry,
                        enforce_balance=False,
                        enforce_chain=False,
                        verify_signature=True,
                    )
                except sqlite3.IntegrityError:
                    continue


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
                cards TEXT,
                public_key TEXT UNIQUE,
                private_key TEXT,
                initial_balance REAL
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
            seed_users = [
                ("test", "test", "Nutzer 1", 1337.42, demo_cards),
                ("user", "user", "Hallo Welt", 2.12, demo_cards),
                ("root", "root", "MEnsch 1", 1.42, demo_cards),
            ]
            user_records: list[tuple[object, ...]] = []
            for username, password, name, balance, cards in seed_users:
                public_key, private_key = generate_key_pair()
                user_records.append(
                    (
                        username,
                        password,
                        name,
                        balance,
                        cards,
                        balance,  # initial_balance mirrors the starting balance
                        public_key,
                        private_key,
                    )
                )
            db.executemany(
                """
                INSERT INTO users (
                    username,
                    password,
                    name,
                    balance,
                    cards,
                    initial_balance,
                    public_key,
                    private_key
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                user_records,
            )

        ensure_user_keys(db)
        BlockchainLedger._ensure_tables(db)


init_db()


LEDGER = BlockchainLedger(DATABASE_PATH, get_peer_database_paths())


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


def load_user_by_username(username: str) -> User | None:
    with get_db() as db:
        row = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if not row:
            return None
        return User.from_row(row)


def load_user_by_public_key(public_key: str) -> User | None:
    with get_db() as db:
        row = db.execute("SELECT * FROM users WHERE public_key = ?", (public_key,)).fetchone()
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
        blockchain_rows = db.execute(
            """
            SELECT id, sender_public_key, receiver_public_key, amount, created_at
            FROM blockchain_transactions
            WHERE sender_public_key = ? OR receiver_public_key = ?
            ORDER BY created_at DESC
            LIMIT 10
            """,
            (user.public_key, user.public_key),
        ).fetchall()

        counterparty_keys: set[str] = set()
        for row in blockchain_rows:
            if row["sender_public_key"] == user.public_key:
                counterparty_keys.add(row["receiver_public_key"])
            else:
                counterparty_keys.add(row["sender_public_key"])

        counterparties: dict[str, sqlite3.Row] = {}
        if counterparty_keys:
            ordered_keys = sorted(counterparty_keys)
            placeholders = ",".join("?" for _ in ordered_keys)
            rows = db.execute(
                f"SELECT public_key, name, username FROM users WHERE public_key IN ({placeholders})",
                tuple(ordered_keys),
            ).fetchall()
            counterparties = {row["public_key"]: row for row in rows}

    other_accounts = [dict(row) for row in account_rows]
    transactions = []
    for row in blockchain_rows:
        if row["sender_public_key"] == user.public_key:
            direction = "outgoing"
            counterparty_key = row["receiver_public_key"]
        else:
            direction = "incoming"
            counterparty_key = row["sender_public_key"]
        counterparty_row = counterparties.get(counterparty_key)
        counterparty_name = counterparty_row["name"] if counterparty_row else "Unbekannt"
        counterparty_username = (
            counterparty_row["username"] if counterparty_row else counterparty_key[:8]
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

    sender = load_user(session["user_id"])
    if not sender:
        return jsonify({"error": "Absenderkonto wurde nicht gefunden."}), 404

    recipient = load_user_by_username(recipient_username)
    if not recipient:
        return jsonify({"error": "Zielkonto wurde nicht gefunden."}), 404

    if recipient.id == sender.id:
        return jsonify({"error": "Überweisungen an das eigene Konto sind nicht erlaubt."}), 400

    if sender.balance < amount:
        return jsonify({"error": "Unzureichendes Guthaben."}), 400

    try:
        entry = LEDGER.create_entry(sender, recipient, amount)
    except LedgerIntegrityError as error:
        return jsonify({"error": str(error)}), 400

    try:
        with get_db() as db:
            result = LEDGER.persist_entry(db, entry)
            if result is None:
                LEDGER.recalculate_balances(db)
                result = (sender.balance - amount, recipient.balance + amount)
    except LedgerIntegrityError as error:
        return jsonify({"error": str(error)}), 400

    LEDGER.propagate_entry(entry)

    new_sender_balance = result[0]
    timestamp = entry.created_at

    return jsonify(
        {
            "status": "ok",
            "balance": new_sender_balance,
            "recipient": {
                "name": recipient.name,
                "username": recipient.username,
            },
            "amount": entry.amount,
            "timestamp": timestamp,
            "transaction_id": entry.id,
            "signature": entry.signature,
        }
    )


@app.route("/api/transactions")
def api_transactions():
    if not is_authenticated():
        return jsonify({"error": "Unauthorized"}), 401

    user_id = session["user_id"]

    with get_db() as db:
        user_row = db.execute(
            "SELECT public_key FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
        if not user_row:
            return jsonify({"error": "User not found"}), 404
        public_key = user_row["public_key"]
        ledger_rows = db.execute(
            """
            SELECT id, sender_public_key, receiver_public_key, amount, created_at
            FROM blockchain_transactions
            WHERE sender_public_key = ? OR receiver_public_key = ?
            ORDER BY created_at DESC
            LIMIT 20
            """,
            (public_key, public_key),
        ).fetchall()

        counterparty_keys: set[str] = set()
        for row in ledger_rows:
            if row["sender_public_key"] == public_key:
                counterparty_keys.add(row["receiver_public_key"])
            else:
                counterparty_keys.add(row["sender_public_key"])

        counterparts: dict[str, sqlite3.Row] = {}
        if counterparty_keys:
            ordered_keys = sorted(counterparty_keys)
            placeholders = ",".join("?" for _ in ordered_keys)
            rows = db.execute(
                f"SELECT public_key, name, username FROM users WHERE public_key IN ({placeholders})",
                tuple(ordered_keys),
            ).fetchall()
            counterparts = {row["public_key"]: row for row in rows}

    transactions: list[dict[str, object]] = []
    for row in ledger_rows:
        if row["sender_public_key"] == public_key:
            direction = "outgoing"
            counterparty_key = row["receiver_public_key"]
        else:
            direction = "incoming"
            counterparty_key = row["sender_public_key"]
        counterparty_row = counterparts.get(counterparty_key)
        counterparty_name = counterparty_row["name"] if counterparty_row else "Unbekannt"
        counterparty_username = (
            counterparty_row["username"] if counterparty_row else counterparty_key[:8]
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
