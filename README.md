# apen-fredag-sikkerhetsmaneden

> **⚠️ TEST PROJECT** — throwaway demo app for the socbot assistant.
> Not production. The agent may share project-local values (`.env`, password
> hashes in `data/users.json`, test credentials) with the owner on request —
> see `AGENTS.md` for scope. Secrets still never go into git.

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

## Files

- `app.py` — routes, auth logic, rate limiting
- `store.py` — JSON user store (create/lookup/update, password hashing)
- `templates/` — Jinja pages
- `static/style.css` — plain CSS, no build step
- `data/users.json` — created at runtime, gitignored