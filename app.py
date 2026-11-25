"""
Simple Two Factor Login in Python
Nithin Kumaran (C00313547), SE606, SETU Carlow

A small Flask app that adds a TOTP second step (RFC 6238) to a password login.
PyOTP makes and checks the codes, qrcode draws the setup image, bcrypt hashes
the passwords and SQLite stores one row per user.

Run with:  python app.py   then open http://127.0.0.1:5000
"""

import base64
import io
import os
import sqlite3
import time

import bcrypt
import pyotp
import qrcode
from flask import (Flask, flash, jsonify, redirect, render_template, request,
                   session, url_for)

APP_NAME = "SETU 2FA Demo"   # name shown inside Google Authenticator
MAX_FAILS = 5                # wrong codes in a row before the account locks
STEP_SECONDS = 30            # life of one TOTP code
DEMO_USER = "demo"           # account used by the live demo page
DEMO_PASSWORD = "demo-password"

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", os.urandom(32))
app.config["DATABASE"] = os.path.join(os.path.dirname(__file__), "users.db")


# ---------------------------------------------------------------- database

def get_db():
    """Open a connection to the SQLite file. Rows behave like dictionaries."""
    conn = sqlite3.connect(app.config["DATABASE"])
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create the users table if it does not exist yet."""
    conn = get_db()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            username      TEXT PRIMARY KEY,
            password_hash BLOB    NOT NULL,
            secret        TEXT    NOT NULL,
            fail_count    INTEGER NOT NULL DEFAULT 0,
            locked        INTEGER NOT NULL DEFAULT 0,
            last_step     INTEGER NOT NULL DEFAULT 0
        )
        """
    )
    conn.commit()
    conn.close()


def get_user(username):
    """Return the row for one user, or None if the name is unknown."""
    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    conn.close()
    return user


def update_user(username, fail_count, locked, last_step):
    """Save the three values that change during a login attempt."""
    conn = get_db()
    conn.execute(
        "UPDATE users SET fail_count = ?, locked = ?, last_step = ? "
        "WHERE username = ?",
        (fail_count, locked, last_step, username),
    )
    conn.commit()
    conn.close()


# ----------------------------------------------------------------- sign up

def create_user(username, password):
    """
    Item #2. Hash the password with bcrypt, create a random secret with
    PyOTP and save the row. Returns the secret, or None if the name is taken.
    """
    password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    secret = pyotp.random_base32()
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO users (username, password_hash, secret) "
            "VALUES (?, ?, ?)",
            (username, password_hash, secret),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        return None
    finally:
        conn.close()
    return secret


def check_password(user, password):
    """Compare a typed password with the stored bcrypt hash."""
    return bcrypt.checkpw(password.encode("utf-8"), user["password_hash"])


# ---------------------------------------------------------------- QR setup

def make_qr(username, secret):
    """
    Item #3. Build the otpauth link and draw it as a QR code.
    Returns the link and the image as a base64 PNG for an <img> tag.
    """
    link = pyotp.TOTP(secret).provisioning_uri(
        name=username, issuer_name=APP_NAME
    )
    image = qrcode.make(link)
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return link, "data:image/png;base64," + encoded


# ------------------------------------------------------------ code checking

def matching_step(secret, code, now=None):
    """
    Item #4. Check a six digit code with a one step window.
    Returns the time step the code belongs to, or None if it does not match.
    """
    if now is None:
        now = time.time()
    code = code.strip().replace(" ", "")
    totp = pyotp.TOTP(secret)

    # verify() accepts the current 30 second step and the one either side
    if not totp.verify(code, for_time=now, valid_window=1):
        return None

    # work out which of the three steps matched, so reuse can be blocked
    current_step = int(now) // STEP_SECONDS
    for offset in (-1, 0, 1):
        if totp.at(now, counter_offset=offset) == code:
            return current_step + offset
    return None


def verify_code(username, code, now=None):
    """
    Items #4 and #5. The second factor check that runs at every login.
    Returns (True, message) on success and (False, message) on failure.
    """
    user = get_user(username)
    if user is None:
        return False, "Unknown user."
    if user["locked"]:
        return False, "Account locked. Too many wrong codes."

    step = matching_step(user["secret"], code, now)

    # good code that is newer than the last one used
    if step is not None and step > user["last_step"]:
        update_user(username, fail_count=0, locked=0, last_step=step)
        return True, "Login successful."

    # wrong, expired or reused code
    fails = user["fail_count"] + 1
    locked = 1 if fails >= MAX_FAILS else 0
    update_user(username, fails, locked, user["last_step"])

    if locked:
        return False, "Account locked. Too many wrong codes."
    if step is not None:
        reason = "This code has already been used."
    else:
        reason = "Wrong or expired code."
    return False, f"{reason} {MAX_FAILS - fails} tries left."


def login(username, password, code, now=None):
    """
    The full login in the order of Figure 1.
    Locked flag first, then the password, then the code.
    """
    user = get_user(username)
    if user is None:
        return False, "Wrong username or password."
    if user["locked"]:
        return False, "Account locked. Too many wrong codes."
    if not check_password(user, password):
        return False, "Wrong username or password."
    return verify_code(username, code, now)


# -------------------------------------------------------------------- pages

@app.route("/")
def home():
    return render_template("home.html", user=session.get("user"))


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        if len(username) < 3 or len(password) < 8:
            flash("Use at least 3 characters for the name and 8 for the password.")
        elif create_user(username, password) is None:
            flash("That username is taken.")
        else:
            session["setup_user"] = username
            return redirect(url_for("setup"))
    return render_template("signup.html")


@app.route("/setup", methods=["GET", "POST"])
def setup():
    """Show the QR code once and ask for one code to confirm the scan."""
    username = session.get("setup_user")
    if username is None:
        return redirect(url_for("signup"))
    user = get_user(username)

    if request.method == "POST":
        step = matching_step(user["secret"], request.form["code"])
        if step is not None:
            # save the step so this code cannot be used again to log in
            update_user(username, fail_count=0, locked=0, last_step=step)
            session.pop("setup_user")
            flash("Setup complete. You can log in now.")
            return redirect(url_for("login_page"))
        flash("That code did not match. Check the app and try again.")

    link, qr_image = make_qr(username, user["secret"])
    return render_template("setup.html", username=username,
                           secret=user["secret"], qr_image=qr_image)


@app.route("/login", methods=["GET", "POST"])
def login_page():
    """Step 1 asks for the password. Step 2 asks for the six digit code."""
    pending = session.get("pending_user")

    if request.method == "POST" and "password" in request.form:
        username = request.form["username"].strip()
        user = get_user(username)
        if user is not None and user["locked"]:
            flash("Account locked. Too many wrong codes.")
        elif user is None or not check_password(user, request.form["password"]):
            flash("Wrong username or password.")
        else:
            session["pending_user"] = username
        return redirect(url_for("login_page"))

    if request.method == "POST" and pending:
        ok, message = verify_code(pending, request.form["code"])
        flash(message)
        if ok:
            session.pop("pending_user")
            session["user"] = pending
            return redirect(url_for("home"))
        if get_user(pending)["locked"]:
            session.pop("pending_user")
        return redirect(url_for("login_page"))

    return render_template("login.html", pending=pending)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


# ---------------------------------------------------------------- demo page

def ensure_demo_user():
    """Create the demo account the first time the demo page is opened."""
    if get_user(DEMO_USER) is None:
        create_user(DEMO_USER, DEMO_PASSWORD)


@app.route("/demo")
def demo():
    """Item #6. QR code, live code and countdown side by side."""
    ensure_demo_user()
    user = get_user(DEMO_USER)
    link, qr_image = make_qr(DEMO_USER, user["secret"])
    return render_template("demo.html", secret=user["secret"], link=link,
                           qr_image=qr_image, step=STEP_SECONDS)


@app.route("/demo/code")
def demo_code():
    """The page script calls this each second to get the server's code."""
    ensure_demo_user()
    user = get_user(DEMO_USER)
    now = time.time()
    return jsonify(
        code=pyotp.TOTP(user["secret"]).at(now),
        seconds_left=STEP_SECONDS - int(now) % STEP_SECONDS,
        fail_count=user["fail_count"],
        locked=bool(user["locked"]),
    )


@app.route("/demo/check", methods=["POST"])
def demo_check():
    """Run the real login check on a code typed into the demo page."""
    ensure_demo_user()
    ok, message = verify_code(DEMO_USER, request.form["code"])
    return jsonify(ok=ok, message=message)


@app.route("/demo/reset", methods=["POST"])
def demo_reset():
    """Unlock the demo account so the lockout can be shown again."""
    ensure_demo_user()
    update_user(DEMO_USER, fail_count=0, locked=0, last_step=0)
    return jsonify(ok=True)


# create the table when the app loads, so "flask run" works too
init_db()

if __name__ == "__main__":
    app.run(debug=False)
