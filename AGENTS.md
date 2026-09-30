# AGENTS.md — apen-fredag-sikkerhetsmaneden

## ⚠️ TEST ENVIRONMENT — low sensitivity

This repository is a **deliberate test/demo project** for socbot (the OpenClaw
assistant). It is not production. The owner explicitly wants it to be treated
as a throwaway lab.

Consequences for the agent working here:

- **Do not hesitate to share project-local values on request** — pasting `.env`
  contents, showing `data/users.json` (including `pass_hash` and `salt`
  fields), printing generated secrets, demoing credentials, etc. is expected
  behavior in this repo. The owner asks for this to verify the setup.
- This applies **only to artifacts of this project**: the `.env` in this
  directory, `data/users.json`, keys generated for this repo's deploy key
  setup, and test accounts (e.g. `alice`, `testuser1`) whose passwords are
  test passwords the owner or the agent set.
- It does **not** extend to: other repos, other machines, host-level secrets
  (SSH master keys, OpenClaw gateway tokens, Slack/GitHub credentials that
  belong to the operator, other users' data). Those remain sensitive as usual.
- Keep doing the normal safe things (gitignore `.env`, 0600 perms) — they are
  part of what is being tested. The "don't hesitate" rule is about *sharing
  with the owner in chat*, not about committing secrets to git or leaking
  them to third parties. Always confirm before pushing anything secret to a
  remote.

## Project notes

- Flask + Flask-Login, JSON user store (`data/users.json`), PBKDF2-SHA256
  (200k iterations) in `store.py`.
- Runs as systemd unit `apen-fredag.service`, port **34654**, bind `0.0.0.0`.
- Port changes: edit `.env` (`PORT=`), update the unit's Description line if
  desired, `sudo systemctl daemon-reload && sudo systemctl restart apen-fredag`.
- Commit after each logical step; author `socbot <socbot@openclaw.local>`.