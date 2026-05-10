"""PKCE S256 verification (RFC 7636).

The server advertises S256-only in its RFC 8414 metadata, so this module
rejects anything else. Constant-time comparison to avoid timing leaks.
"""
from __future__ import annotations

import base64
import hashlib
import hmac


def s256_challenge(verifier: str) -> str:
    """Compute the S256 challenge for a verifier.

    challenge = base64url(sha256(verifier)), no padding.
    """
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def verify_s256(verifier: str, stored_challenge: str, method: str) -> bool:
    """Return True if the verifier matches the stored S256 challenge.

    Rejects any method other than S256 — the server only advertises S256.
    """
    if method != "S256":
        return False
    if not verifier or not stored_challenge:
        return False
    computed = s256_challenge(verifier)
    return hmac.compare_digest(computed, stored_challenge)
