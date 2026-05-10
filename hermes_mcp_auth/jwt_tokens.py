"""HS256 access token issuance and validation.

Single-user system, single signing key, short-lived access tokens (1h).
Refresh tokens are opaque strings stored in the file-backed OAuthStore; only
access tokens are JWTs.

Claims:
  sub  = "dillon"          (single-user)
  iss  = settings.public_origin
  aud  = "hermes-mcp"
  iat  = issuance time
  exp  = expiry (iat + 3600)
  jti  = unique token id
  scp  = space-delimited scope string
"""
from __future__ import annotations

import logging
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path

import jwt

ACCESS_TTL = 60 * 60         # 1 hour
ALGORITHM = "HS256"
AUDIENCE = "hermes-mcp"
SUBJECT = "dillon"


class SigningKeyMissing(RuntimeError):
    """Raised when the signing key file is absent or empty."""


def load_signing_key(path: Path) -> str:
    """Read the HS256 signing key from disk.

    Auto-generates on first run (single-user dev pattern). Warn if the file
    has loose permissions.
    """
    ensure_signing_key(path)
    key = path.read_text().strip()
    if not key:
        raise SigningKeyMissing(f"oauth signing key at {path} is empty")
    mode = path.stat().st_mode & 0o777
    if mode & 0o077:
        logging.getLogger("hermes.mcp_auth").warning(
            "oauth signing key %s has permissive mode %o — expected 600", path, mode
        )
    return key


def ensure_signing_key(path: Path) -> None:
    """Create the signing key file if it does not exist."""
    if path.exists() and path.read_text().strip():
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(secrets.token_urlsafe(48))
    os.chmod(path, 0o600)


@dataclass(frozen=True)
class AccessToken:
    jwt_str: str
    expires_in: int
    jti: str


def issue_access_token(
    *,
    signing_key: str,
    issuer: str,
    client_id: str,
    scope: str,
) -> AccessToken:
    now = int(time.time())
    exp = now + ACCESS_TTL
    jti = secrets.token_urlsafe(16)
    payload = {
        "sub": SUBJECT,
        "iss": issuer,
        "aud": AUDIENCE,
        "iat": now,
        "exp": exp,
        "jti": jti,
        "client_id": client_id,
        "scp": scope,
    }
    token = jwt.encode(payload, signing_key, algorithm=ALGORITHM)
    return AccessToken(jwt_str=token, expires_in=ACCESS_TTL, jti=jti)


@dataclass(frozen=True)
class ValidatedToken:
    sub: str
    jti: str
    client_id: str
    scope: str


def validate_access_token(
    *,
    token: str,
    signing_key: str,
    issuer: str,
    audience: str = AUDIENCE,
) -> ValidatedToken:
    """Raises ``jwt.InvalidTokenError`` subclasses on failure.

    ``audience`` defaults to Hermes's native ``hermes-mcp`` audience, but is
    configurable so Hermes can also act as a resource server behind another
    trusted local authorization server (currently Reid's root OAuth issuer,
    which emits ``aud=reid-v7``).
    """
    payload = jwt.decode(
        token,
        signing_key,
        algorithms=[ALGORITHM],
        audience=audience,
        issuer=issuer,
        options={"require": ["exp", "iat", "iss", "aud", "sub"]},
    )
    return ValidatedToken(
        sub=payload["sub"],
        jti=payload.get("jti", ""),
        client_id=payload.get("client_id", ""),
        scope=payload.get("scp", ""),
    )
