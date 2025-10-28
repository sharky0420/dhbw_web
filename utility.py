import dataclasses
import datetime
import json
import math
import sqlite3


@dataclasses.dataclass()
class User():
    id: int
    username: str
    password: str
    name: str
    balance: float = 0.0
    cards: list[dict[str, str]] | None = None
    public_key: str | None = None
    private_key: str | None = None

    @staticmethod
    def from_row(row: sqlite3.Row) -> "User":
        cards_raw = row["cards"] if "cards" in row.keys() else None
        cards = json.loads(cards_raw) if cards_raw else []
        public_key = row["public_key"] if "public_key" in row.keys() else None
        private_key = row["private_key"] if "private_key" in row.keys() else None

        return User(
            id=row["id"],
            username=row["username"],
            password=row["password"],
            name=row["name"],
            balance=row["balance"],
            cards=cards,
            public_key=public_key,
            private_key=private_key,
        )

@dataclasses.dataclass()
class Transaction():
    id: int
    sender_public_key: str
    receiver_public_key: str
    amount: float
    created_at: str | None = None

    @staticmethod
    def from_row(row: sqlite3.Row) -> "User":
        return Transaction(
            id=row["id"],
            sender_public_key=row["sender_public_key"],
            receiver_public_key=row["receiver_public_key"],
            amount=row["amount"],
            created_at=row["created_at"]
        )

    def is_user_sender(self, user: User) -> bool:
        return self.sender_public_key == user.public_key


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

    now = datetime.datetime.utcnow()
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
