"""File-backed OAuth state store.

Persists clients, authorization codes, and refresh tokens as a single JSON
file (default ~/.config/reid/oauth-state.json, mode 0600). Concurrency is
handled with `fcntl.flock` — the server runs as one uvicorn process, so the
lock is mostly belt-and-suspenders for manual shell edits.

GC policy:
  * Authorization codes: expire after 5 minutes OR after single use.
  * Refresh tokens: expire after 30 days, rotate on use.
  * Client registrations: GC'd if no refresh tokens and no activity for 7 days.

Everything garbage-collects on every write (the store is small enough that
O(n) sweep is free at single-user scale).
"""
from __future__ import annotations

import fcntl
import json
import os
import secrets
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

# TTLs in seconds.
CODE_TTL = 5 * 60                    # 5 minutes
REFRESH_TTL = 30 * 24 * 60 * 60      # 30 days
CLIENT_IDLE_TTL = 7 * 24 * 60 * 60   # 7 days with no activity


@dataclass(frozen=True)
class Client:
    client_id: str
    client_name: str
    redirect_uris: list[str]
    created_at: float


@dataclass(frozen=True)
class AuthCode:
    code: str
    client_id: str
    redirect_uri: str
    code_challenge: str
    code_challenge_method: str
    scope: str
    expires_at: float


@dataclass(frozen=True)
class RefreshToken:
    token: str
    client_id: str
    issued_at: float
    expires_at: float


def _empty_state() -> dict[str, Any]:
    return {"clients": {}, "codes": {}, "refresh_tokens": {}}


class OAuthStore:
    """Thin wrapper around a JSON file with an advisory file lock.

    Usage: every read-modify-write call goes through `self._with_lock(...)`
    which re-reads the file under flock, runs a mutator, writes atomically,
    and returns the mutator's result. Pure reads (list_clients, etc.) also
    acquire a shared lock but skip the write phase.
    """

    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self._write_raw(_empty_state())
            os.chmod(self.path, 0o600)

    # ---------- low-level file I/O ----------

    def _write_raw(self, state: dict[str, Any]) -> None:
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(state, indent=2, sort_keys=True))
        os.chmod(tmp, 0o600)
        tmp.replace(self.path)

    @contextmanager
    def _lock(self, exclusive: bool) -> Iterator[Any]:
        # Open a separate lock file to avoid truncating the state file on open.
        lock_path = self.path.with_suffix(self.path.suffix + ".lock")
        with open(lock_path, "a+") as fh:
            fcntl.flock(fh, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
            try:
                yield fh
            finally:
                fcntl.flock(fh, fcntl.LOCK_UN)

    def _load(self) -> dict[str, Any]:
        try:
            raw = self.path.read_text()
        except FileNotFoundError:
            return _empty_state()
        if not raw.strip():
            return _empty_state()
        state = json.loads(raw)
        # Backfill any missing top-level keys for forward-compat.
        for key, default in _empty_state().items():
            state.setdefault(key, default)
        return state

    def _gc(self, state: dict[str, Any]) -> None:
        """Remove expired codes and refresh tokens, prune idle clients."""
        now = time.time()

        # Codes: drop if expired OR used.
        state["codes"] = {
            k: v
            for k, v in state["codes"].items()
            if v.get("expires_at", 0) > now and not v.get("used", False)
        }

        # Refresh tokens: drop if expired OR revoked.
        state["refresh_tokens"] = {
            k: v
            for k, v in state["refresh_tokens"].items()
            if v.get("expires_at", 0) > now and not v.get("revoked", False)
        }

        # Clients: drop if idle (no refresh tokens, no codes, created long ago).
        active_client_ids = {v["client_id"] for v in state["refresh_tokens"].values()}
        active_client_ids.update(v["client_id"] for v in state["codes"].values())
        state["clients"] = {
            k: v
            for k, v in state["clients"].items()
            if k in active_client_ids or (now - v.get("created_at", 0)) < CLIENT_IDLE_TTL
        }

    # ---------- public API ----------

    def gc(self) -> dict[str, int]:
        """Force a garbage collection sweep. Returns counts {clients, codes, refresh_tokens}
        of how many items were removed. Used by the nightly maintenance job."""
        with self._lock(exclusive=True):
            state = self._load()
            before = {
                "clients": len(state.get("clients", {})),
                "codes": len(state.get("codes", {})),
                "refresh_tokens": len(state.get("refresh_tokens", {})),
            }
            self._gc(state)
            after = {
                "clients": len(state.get("clients", {})),
                "codes": len(state.get("codes", {})),
                "refresh_tokens": len(state.get("refresh_tokens", {})),
            }
            self._write_raw(state)
        return {k: before[k] - after[k] for k in before}

    def register_client(self, client_name: str, redirect_uris: list[str]) -> Client:
        if not redirect_uris:
            raise ValueError("at least one redirect_uri required")
        client_id = secrets.token_urlsafe(16)
        now = time.time()
        with self._lock(exclusive=True):
            state = self._load()
            self._gc(state)
            state["clients"][client_id] = {
                "client_id": client_id,
                "client_name": client_name,
                "redirect_uris": list(redirect_uris),
                "created_at": now,
            }
            self._write_raw(state)
        return Client(
            client_id=client_id,
            client_name=client_name,
            redirect_uris=list(redirect_uris),
            created_at=now,
        )

    def get_client(self, client_id: str) -> Client | None:
        with self._lock(exclusive=False):
            state = self._load()
        raw = state["clients"].get(client_id)
        if not raw:
            return None
        return Client(
            client_id=raw["client_id"],
            client_name=raw["client_name"],
            redirect_uris=list(raw["redirect_uris"]),
            created_at=raw["created_at"],
        )

    def issue_code(
        self,
        *,
        client_id: str,
        redirect_uri: str,
        code_challenge: str,
        code_challenge_method: str,
        scope: str,
    ) -> AuthCode:
        code = secrets.token_urlsafe(32)
        now = time.time()
        expires_at = now + CODE_TTL
        with self._lock(exclusive=True):
            state = self._load()
            self._gc(state)
            if client_id not in state["clients"]:
                raise KeyError(f"unknown client_id: {client_id}")
            if redirect_uri not in state["clients"][client_id]["redirect_uris"]:
                raise ValueError("redirect_uri not registered for client")
            state["codes"][code] = {
                "code": code,
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "code_challenge": code_challenge,
                "code_challenge_method": code_challenge_method,
                "scope": scope,
                "expires_at": expires_at,
                "used": False,
            }
            self._write_raw(state)
        return AuthCode(
            code=code,
            client_id=client_id,
            redirect_uri=redirect_uri,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            scope=scope,
            expires_at=expires_at,
        )

    def consume_code(self, code: str) -> AuthCode | None:
        """Atomically fetch + mark the code as used. Returns None if already used or missing."""
        with self._lock(exclusive=True):
            state = self._load()
            self._gc(state)
            raw = state["codes"].get(code)
            if not raw or raw.get("used", False):
                return None
            if raw["expires_at"] <= time.time():
                return None
            raw["used"] = True
            state["codes"][code] = raw
            self._write_raw(state)
        return AuthCode(
            code=raw["code"],
            client_id=raw["client_id"],
            redirect_uri=raw["redirect_uri"],
            code_challenge=raw["code_challenge"],
            code_challenge_method=raw["code_challenge_method"],
            scope=raw["scope"],
            expires_at=raw["expires_at"],
        )

    def issue_refresh_token(self, client_id: str) -> RefreshToken:
        token = secrets.token_urlsafe(48)
        now = time.time()
        expires_at = now + REFRESH_TTL
        with self._lock(exclusive=True):
            state = self._load()
            self._gc(state)
            state["refresh_tokens"][token] = {
                "token": token,
                "client_id": client_id,
                "issued_at": now,
                "expires_at": expires_at,
                "revoked": False,
            }
            self._write_raw(state)
        return RefreshToken(
            token=token, client_id=client_id, issued_at=now, expires_at=expires_at
        )

    def rotate_refresh_token(self, old_token: str) -> tuple[RefreshToken, str] | None:
        """Revoke old_token and issue a new one. Returns (new, client_id) or None."""
        with self._lock(exclusive=True):
            state = self._load()
            self._gc(state)
            raw = state["refresh_tokens"].get(old_token)
            if not raw or raw.get("revoked", False) or raw["expires_at"] <= time.time():
                return None
            client_id = raw["client_id"]
            # Revoke the old one.
            raw["revoked"] = True
            state["refresh_tokens"][old_token] = raw
            # Issue a new one inline (can't call issue_refresh_token — we hold the lock).
            new_token = secrets.token_urlsafe(48)
            now = time.time()
            new_expires_at = now + REFRESH_TTL
            state["refresh_tokens"][new_token] = {
                "token": new_token,
                "client_id": client_id,
                "issued_at": now,
                "expires_at": new_expires_at,
                "revoked": False,
            }
            self._write_raw(state)
        return (
            RefreshToken(
                token=new_token,
                client_id=client_id,
                issued_at=now,
                expires_at=new_expires_at,
            ),
            client_id,
        )
