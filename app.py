from flask import Flask, render_template, request, redirect, url_for, session, flash

app = Flask(__name__)
app.secret_key = "retro-bank-secret-key"

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

        if (
            username == USER_CREDENTIALS["username"]
            and password == USER_CREDENTIALS["password"]
        ):
            session["logged_in"] = True
            flash("Erfolgreich angemeldet!", "success")
            return redirect(url_for("account"))

        flash("Ungültiger Login. Bitte erneut versuchen.", "error")

    if is_authenticated():
        return redirect(url_for("account"))

    return render_template("login.html")


@app.route("/account")
def account():
    if not is_authenticated():
        flash("Bitte melden Sie sich zuerst an.", "error")
        return redirect(url_for("login"))

    balance_usd = USER_CREDENTIALS["balance"]
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
        username=USER_CREDENTIALS["username"],
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
