"""Bearer auth middleware for the Hermes MCP endpoint.

Guards /mcp/* requests behind a valid OAuth 2.1 access token. Allow-lists
/health, /.well-known/*, and /oauth/* so discovery and the token dance can
complete without authentication.

On missing/invalid token, returns 401 with a WWW-Authenticate header whose
``resource_metadata`` points at the RFC 9728 protected-resource metadata URL
— that's how claude.ai's MCP connector discovers the authorization server
without prior configuration.
"""
from __future__ import annotations

import logging

import jwt
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from hermes_mcp_auth.jwt_tokens import validate_access_token

log = logging.getLogger("hermes.mcp_auth.middleware")

# Paths that never require authentication.
_ALLOWLIST_PREFIXES = (
    "/health",
    "/.well-known/",
    "/oauth/",
    "/register",
)


def _is_guarded_path(path: str) -> bool:
    if path == "/mcp" or path.startswith("/mcp/"):
        return True
    return False


def _allowed_without_auth(path: str) -> bool:
    return any(path == p.rstrip("/") or path.startswith(p) for p in _ALLOWLIST_PREFIXES)


class OAuthBearerMiddleware(BaseHTTPMiddleware):
    """Starlette middleware enforcing OAuth-issued JWT bearer auth on /mcp/*.

    Distinct from the static-bearer middleware in mcp_serve.py — this one
    validates JWTs against the OAuth signing key and supports RFC 9728
    discovery metadata in the 401 response.
    """

    def __init__(self, app, *, signing_key: str, issuer: str, audience: str = "hermes-mcp"):
        super().__init__(app)
        self._signing_key = signing_key
        self._issuer = issuer
        self._audience = audience
        self._www_authenticate = (
            f'Bearer resource_metadata="{issuer}/.well-known/oauth-protected-resource/mcp", '
            f'error="invalid_token"'
        )

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        if not _is_guarded_path(path):
            return await call_next(request)

        if _allowed_without_auth(path):
            return await call_next(request)

        auth_header = request.headers.get("authorization", "")
        if not auth_header.lower().startswith("bearer "):
            return self._unauthorized("missing bearer token")

        token = auth_header.split(" ", 1)[1].strip()
        if not token:
            return self._unauthorized("empty bearer token")

        try:
            validated = validate_access_token(
                token=token,
                signing_key=self._signing_key,
                issuer=self._issuer,
                audience=self._audience,
            )
        except jwt.ExpiredSignatureError:
            log.info("reject /mcp request: expired token")
            return self._unauthorized("token expired")
        except jwt.InvalidTokenError as e:
            log.info("reject /mcp request: invalid token (%s)", type(e).__name__)
            return self._unauthorized("invalid token")

        request.state.auth_subject = validated.sub
        request.state.auth_client_id = validated.client_id
        request.state.auth_scope = validated.scope
        return await call_next(request)

    def _unauthorized(self, detail: str) -> JSONResponse:
        return JSONResponse(
            status_code=401,
            content={"error": "invalid_token", "error_description": detail},
            headers={"WWW-Authenticate": self._www_authenticate},
        )
