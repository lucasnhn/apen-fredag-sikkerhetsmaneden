"""apen-fredag-sikkerhetsmaneden — Flask + Flask-Login multi-user auth app.

Run:  ./venv/bin/python app.py   (reads .env from the project root)
"""

import os
import secrets
import time
from collections import defaultdict, deque
from functools import wraps
from pathlib import Path

from flask import (
    Flask, abort, flash, g, jsonify, redirect, render_template, request, session,
    url_for,
)
from flask_login import (
    LoginManager, UserMixin, current_user, login_required, login_user, logout_user,
)

from store import User, UserStore

# ---------------------------------------------------------------- config

BASE_DIR = Path(__file__).resolve().parent


def load_env_file(path: Path) -> None:
    """Minimal .env loader: KEY=VALUE lines, no quoting magic, no secrets
    overwrite already-set environment variables."""
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip())


load_env_file(BASE_DIR / ".env")

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or "dev-only-insecure-key-change-me"
if app.secret_key == "dev-only-insecure-key-change-me":
    print("WARNING: SECRET_KEY not set in .env — sessions are NOT secure. "
          "Generate one: python3 -c \"import secrets; print(secrets.token_hex(32))\"")

store = UserStore(str(BASE_DIR / "data" / "users.json"))

# Flask-Login wiring
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Sign in to view this page."
login_manager.login_message_category = "info"


@login_manager.user_loader
def load_user(user_id: str) -> User | None:
    return store.get(int(user_id))


class AuthUser(UserMixin):
    """Flask-Login wrapper around a store User."""

    def __init__(self, user: User):
        self.user = user
        self.id = str(user.id)
        self.is_active = True

    @property
    def username(self) -> str:
        return self.user.username


# ------------------------------------------------------------- csrf (tiny, stdlib)

def _csrf_secret() -> bytes:
    return app.secret_key.encode("utf-8")


def csrf_token() -> str:
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


def check_csrf() -> bool:
    expected = session.get("csrf")
    sent = request.form.get("csrf", "")
    return bool(expected) and secrets.compare_digest(expected, sent)


def csrf_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not check_csrf():
            abort(400, description="Invalid CSRF token.")
        return view(*args, **kwargs)
    return wrapped


# ------------------------------------------------------------- login rate limit

_RATE_LIMIT = 5          # max attempts
_RATE_WINDOW = 60        # seconds
_attempts: dict[str, deque] = defaultdict(deque)


def rate_limited(ip: str) -> bool:
    now = time.time()
    q = _attempts[ip]
    while q and now - q[0] > _RATE_WINDOW:
        q.popleft()
    if len(q) >= _RATE_LIMIT:
        return True
    q.append(now)
    return False


def ip() -> str:
    return request.remote_addr or "?"


# ------------------------------------------------------------- validation

def valid_username(username: str) -> bool:
    return 3 <= len(username.strip()) <= 32


def valid_password(password: str) -> bool:
    return len(password) >= 8


# ------------------------------------------------------------- routes

@app.context_processor
def inject_csrf():
    return {"csrf_token": csrf_token()}


@app.template_filter("human_time")
def human_time(iso: str) -> str:
    from datetime import datetime
    return datetime.fromisoformat(iso).strftime("%Y-%m-%d %H:%M")


@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if not check_csrf():
            abort(400, description="Invalid CSRF token.")
        if rate_limited(ip()):
            flash("Too many sign-in attempts — try again in a minute.", "error")
            return render_template("login.html"), 429
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = store.get_by_username(username)
        if user and store.check_password(user, password):
            remember = request.form.get("remember") == "on"
            login_user(AuthUser(user), remember=remember)
            session["login_time"] = time.strftime("%Y-%m-%d %H:%M:%S")
            next_url = request.args.get("next") or url_for("dashboard")
            return redirect(next_url)
        flash("Invalid username or password.", "error")
        return render_template("login.html"), 401
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        if not check_csrf():
            abort(400, description="Invalid CSRF token.")
        if rate_limited(ip()):
            flash("Too many attempts — try again in a minute.", "error")
            return render_template("register.html"), 429

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("password2", "")
        errors = []
        if not valid_username(username):
            errors.append("Username must be 3–32 characters.")
        if not valid_password(password):
            errors.append("Password must be at least 8 characters.")
        if password != confirm:
            errors.append("Passwords do not match.")
        if not errors and store.get_by_username(username) is not None:
            errors.append("That username is already taken.")
        if errors:
            for e in errors:
                flash(e, "error")
            return render_template("register.html", username=username), 400

        store.create(username, password)
        flash("Account created — sign in.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/logout", methods=["POST"])
@login_required
@csrf_required
def logout():
    session.pop("login_time", None)
    logout_user()
    flash("Signed out.", "info")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template(
        "dashboard.html",
        username=current_user.username,
        login_time=session.get("login_time", "unknown"),
        user_agent=request.headers.get("User-Agent", "")[:60],
        remember=bool(request.cookies.get(login_manager.remember_cookie_name or "remember")),
    )


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        if not check_csrf():
            abort(400, description="Invalid CSRF token.")
        current = request.form.get("current", "")
        new = request.form.get("new", "")
        confirm = request.form.get("new2", "")
        user = store.get(current_user.id)
        if not user or not store.check_password(user, current):
            flash("Current password is incorrect.", "error")
            return render_template("profile.html"), 400
        if not valid_password(new):
            flash("New password must be at least 8 characters.", "error")
            return render_template("profile.html"), 400
        if new != confirm:
            flash("New passwords do not match.", "error")
            return render_template("profile.html"), 400
        store.change_password(user, new)
        flash("Password updated.", "success")
        return redirect(url_for("profile"))
    user = store.get(current_user.id)
    return render_template("profile.html", created_at=user.created_at)


# ------------------------------------------------------------- health & errors

@app.route("/healthz")
def healthz():
    return jsonify(status="ok")


@app.errorhandler(404)
def not_found(_):
    return render_template("404.html"), 404


@app.errorhandler(500)
def server_error(_):
    return render_template("500.html"), 500


# ------------------------------------------------------------- security headers

@app.after_request
def security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "same-origin")
    resp.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'self'",
    )
    return resp


if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8000"))
    app.run(host=host, port=port, debug=False)