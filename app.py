from flask import Flask, render_template, request, redirect, url_for, session, flash

app = Flask(__name__)
app.secret_key = "retro-bank-secret-key"

USER_CREDENTIALS = {
    "username": "test",
    "password": "test",
    "balance": 1337.42,
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

    return render_template(
        "account.html",
        balance=USER_CREDENTIALS["balance"],
        username=USER_CREDENTIALS["username"],
    )


@app.route("/logout")
def logout():
    session.clear()
    flash("Sie wurden abgemeldet.", "info")
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)
