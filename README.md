# apen-fredag-sikkerhetsmaneden

A small Flask web app with multi-user authentication.

- Flask + Flask-Login (the only two dependencies)
- JSON file user store (no database)
- PBKDF2-SHA256 password hashing (stdlib)
- Signed-cookie sessions, CSRF protection, login rate limiting

## Setup

```bash
python3 -m venv venv
./venv/bin/pip install -r requirements.txt
cp .env.example .env   # then set SECRET_KEY
./venv/bin/python app.py
```

Open http://127.0.0.1:8000, register an account, sign in.

## Optional: self-signed HTTPS

Enable with `USE_SSL=1` in `.env` (or `--ssl` on the command line):

```bash
USE_SSL=1 ./venv/bin/python app.py   # or: ./venv/bin/python app.py --ssl
```

- On first run a self-signed cert + key are generated with `openssl` and stored in `certs/` (gitignored); they are reused across restarts.
- The session cookie gets the `Secure` flag, so cookies only travel over HTTPS.
- Your browser will warn that the certificate is not trusted — expected for a self-signed cert; click through to continue.
- Requires `openssl` on the system.

## Files

- `app.py` — routes, auth logic, rate limiting
- `store.py` — JSON user store (create/lookup/update, password hashing)
- `templates/` — Jinja pages
- `static/style.css` — plain CSS, no build step
- `data/users.json` — created at runtime, gitignored