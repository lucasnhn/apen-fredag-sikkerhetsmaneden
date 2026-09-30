"""JSON file user store with PBKDF2-SHA256 password hashing.

No database: users live in data/users.json (gitignored, 0600).
All mutations go through this module, which holds a lock and writes
atomically (temp file + rename) so a crash can't corrupt the store.
"""

import hashlib
import hmac
import json
import os
import secrets
import threading
from dataclasses import dataclass
from datetime import datetime, timezone

PBKDF2_ITERATIONS = 200_000


@dataclass
class User:
    id: int
    username: str
    created_at: str
    pass_hash: str = ""
    salt: str = ""


class UserStore:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        if not os.path.exists(path):
            self._write({"users": {}, "seq": 0})

    # -- persistence -------------------------------------------------

    def _read(self) -> dict:
        with open(self.path, encoding="utf-8") as f:
            return json.load(f)

    def _write(self, data: dict) -> None:
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, self.path)
        os.chmod(self.path, 0o600)

    # -- password hashing (stdlib only) ------------------------------

    @staticmethod
    def hash_password(password: str, salt: str) -> str:
        return hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt), PBKDF2_ITERATIONS
        ).hex()

    @classmethod
    def verify_password(cls, password: str, salt: str, expected_hash: str) -> bool:
        actual = cls.hash_password(password, salt)
        return hmac.compare_digest(actual, expected_hash)

    # -- operations ---------------------------------------------------

    def get(self, user_id: int) -> User | None:
        with self._lock:
            data = self._read()
        raw = data["users"].get(str(user_id))
        if raw is None:
            return None
        return User(**{**raw, "id": user_id})

    def get_by_username(self, username: str) -> User | None:
        uname = username.strip().lower()
        with self._lock:
            data = self._read()
        for raw in data["users"].values():
            if raw["username"].lower() == uname:
                return User(**raw)
        return None

    def create(self, username: str, password: str) -> User:
        salt = secrets.token_hex(16)
        user = User(
            id=0,
            username=username.strip(),
            created_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            salt=salt,
            pass_hash=self.hash_password(password, salt),
        )
        with self._lock:
            data = self._read()
            user.id = data["seq"] + 1
            data["seq"] = user.id
            data["users"][str(user.id)] = {
                "id": user.id,
                "username": user.username,
                "created_at": user.created_at,
                "salt": user.salt,
                "pass_hash": user.pass_hash,
            }
            self._write(data)
        return user

    def check_password(self, user: User, password: str) -> bool:
        return self.verify_password(password, user.salt, user.pass_hash)

    def change_password(self, user: User, new_password: str) -> None:
        salt = secrets.token_hex(16)
        with self._lock:
            data = self._read()
            raw = data["users"][str(user.id)]
            raw["salt"] = salt
            raw["pass_hash"] = self.hash_password(new_password, salt)
            self._write(data)