from flask import Flask, render_template, request, redirect, url_for, session, flash
from dataclasses import dataclass

@dataclass
class User():
    username: str
    password: str
    name: str
    balance: float = 0.0

    def from_json(data: dict[str, any]) -> "User":
        return User(
            data.get("username", ""),
            data.get("password", ""),
            data.get("name", ""),
            data.get("balance", 0.0)
        )

app = Flask(__name__)
app.secret_key = "retro-bank-secret-key"

users: list[User] = [
    User("test", "test", "Nutzer 1", 1337.42),
    User("user", "user", "Hallo Welt", 2.12),
    User("root", "root", "MEnsch 1", 1.42)
]

USER_CREDENTIALS = {
    "username": "test",
    "password": "test",
    "balance": 1337.42,
}

# Wechselkurse aus dem Jahr 2000 (ca.) pro 1 US-Dollar
CURRENCY_RATES_2000 = {
    "DEM": {"name": "Deutsche Mark", "per_usd": 2.04, "symbol": "DM"},
    "FRF": {"name": "Französischer Franc", "per_usd": 6.75, "symbol": "F"},
    "ITL": {"name": "Italienische Lira", "per_usd": 2031.00, "symbol": "₤"},
    "ESP": {"name": "Spanische Peseta", "per_usd": 170.00, "symbol": "₧"},
    "ATS": {"name": "Österreichischer Schilling", "per_usd": 14.20, "symbol": "S"},
    "NLG": {"name": "Niederländischer Gulden", "per_usd": 2.18, "symbol": "ƒ"},
    "BEF": {"name": "Belgischer Franc", "per_usd": 41.00, "symbol": "FB"},
}


def match_user(username: str, password: str) -> User | None:
    for user in users:
        if username == user.username and password == user.password:
            return user
    return None


def is_authenticated() -> bool:
    return session.get("logged_in", False)


@app.route("/")
def index():
    if is_authenticated():
        return redirect(url_for("account"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = match_user(username, password)
        if user:
            session["logged_in"] = True
            session["user"] = user
            flash("Erfolgreich angemeldet!", "success")
            return redirect(url_for("account"))

        flash("Ungültiger Login. Bitte erneut versuchen.", "error")

    if is_authenticated():
        return redirect(url_for("account"))

    return render_template("login.html")


@app.route("/account")
def account():
    if not is_authenticated() or not session.get("user"):
        flash("Bitte melden Sie sich zuerst an.", "error")
        return redirect(url_for("login"))
    user: User = User.from_json(session.get("user"))

    balance_usd = user.balance
    converted_balances = [
        {
            "code": code,
            "name": data["name"],
            "value": balance_usd * data["per_usd"],
            "symbol": data["symbol"],
            "rate": data["per_usd"],
        }
        for code, data in CURRENCY_RATES_2000.items()
    ]

    return render_template(
        "account.html",
        balance=balance_usd,
        username=user.name,
        base_currency="USD",
        conversions=sorted(converted_balances, key=lambda entry: entry["code"]),
    )


@app.route("/logout")
def logout():
    session.clear()
    flash("Sie wurden abgemeldet.", "info")
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)
