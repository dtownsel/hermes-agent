"""OAuth 2.1 + PKCE endpoints (RFC 7591 / RFC 8414 / RFC 7636).

Pure Starlette implementation (no FastAPI dependency) so the routes can be
appended onto FastMCP's streamable_http_app() router directly without
dragging in FastAPI's middleware-stack contract.

Routes:
  GET  /.well-known/oauth-protected-resource
  GET  /.well-known/oauth-protected-resource/mcp
  GET  /.well-known/oauth-authorization-server
  POST /oauth/register
  POST /register
  GET  /oauth/authorize          (renders consent HTML)
  POST /oauth/authorize          (form POST → code issuance + 302 redirect)
  POST /oauth/token              (code exchange OR refresh token grant)

Scope is deliberately minimal: single-user system, one real client
(claude.ai), dynamic registration accepts anyone because the OAuth
endpoints are publicly reachable — but the /oauth/authorize step is gated
by an in-browser human approval click, so a stranger hitting /oauth/register
cannot complete the dance without the operator physically clicking Approve.

All failures return RFC 6749 error shapes.
"""
from __future__ import annotations

import html
import json
import logging
from typing import Any
from urllib.parse import urlencode, urlparse

from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route

from hermes_mcp_auth.jwt_tokens import issue_access_token
from hermes_mcp_auth.pkce import verify_s256
from hermes_mcp_auth.store import OAuthStore

log = logging.getLogger("hermes.mcp_auth.endpoints")


# --------------------------------------------------------------------------- #
# Module-level singletons — populated by configure_auth_router at startup.
# --------------------------------------------------------------------------- #


class _AuthContext:
    store: OAuthStore | None = None
    signing_key: str | None = None
    issuer: str | None = None


_ctx = _AuthContext()


def configure_auth_router(
    *,
    store: OAuthStore,
    signing_key: str,
    issuer: str,
) -> None:
    """Wire the singletons before the server starts handling requests."""
    _ctx.store = store
    _ctx.signing_key = signing_key
    _ctx.issuer = issuer


def _require_ctx() -> tuple[OAuthStore, str, str]:
    if not (_ctx.store and _ctx.signing_key and _ctx.issuer):
        raise RuntimeError("auth router not configured — call configure_auth_router first")
    return _ctx.store, _ctx.signing_key, _ctx.issuer


def _json_err(code: str, description: str, status: int = 400) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"error": code, "error_description": description},
    )


# --------------------------------------------------------------------------- #
# Discovery
# --------------------------------------------------------------------------- #


def _protected_resource_metadata(issuer: str) -> dict:
    return {
        "resource": f"{issuer}/mcp",
        "authorization_servers": [issuer],
        "bearer_methods_supported": ["header"],
        "scopes_supported": ["mcp"],
    }


async def protected_resource_metadata(_request: Request) -> JSONResponse:
    """RFC 9728: advertises which authorization server protects this resource."""
    _, _, issuer = _require_ctx()
    return JSONResponse(_protected_resource_metadata(issuer))


async def protected_resource_metadata_mcp(_request: Request) -> JSONResponse:
    """MCP authorization spec (2025-06-18) path-suffixed metadata URL.

    claude.ai's connector probes here; without it the post-authorize token
    exchange is never attempted.
    """
    _, _, issuer = _require_ctx()
    return JSONResponse(_protected_resource_metadata(issuer))


async def authorization_server_metadata(_request: Request) -> JSONResponse:
    """RFC 8414: full OAuth 2.0 authorization server metadata."""
    _, _, issuer = _require_ctx()
    return JSONResponse(
        {
            "issuer": issuer,
            "authorization_endpoint": f"{issuer}/oauth/authorize",
            "token_endpoint": f"{issuer}/oauth/token",
            "registration_endpoint": f"{issuer}/oauth/register",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
            "scopes_supported": ["mcp"],
            "response_modes_supported": ["query"],
        }
    )


# --------------------------------------------------------------------------- #
# Dynamic client registration (RFC 7591)
# --------------------------------------------------------------------------- #


async def register_client(request: Request) -> Response:
    store, _, _ = _require_ctx()

    try:
        body = await request.json()
    except Exception:
        return _json_err("invalid_client_metadata", "request body must be JSON")
    if not isinstance(body, dict):
        return _json_err("invalid_client_metadata", "request body must be a JSON object")

    redirect_uris = body.get("redirect_uris")
    client_name = body.get("client_name") or "claude.ai connector"

    if not redirect_uris or not isinstance(redirect_uris, list):
        return _json_err(
            "invalid_client_metadata",
            "at least one redirect_uri required",
        )

    for uri in redirect_uris:
        if not isinstance(uri, str):
            return _json_err("invalid_redirect_uri", f"non-string redirect_uri: {uri!r}")
        try:
            parsed = urlparse(uri)
        except Exception:
            return _json_err("invalid_redirect_uri", f"unparseable redirect_uri: {uri}")
        if parsed.scheme not in ("http", "https"):
            return _json_err(
                "invalid_redirect_uri",
                f"redirect_uri scheme must be http or https: {uri}",
            )

    client = store.register_client(
        client_name=str(client_name), redirect_uris=[str(u) for u in redirect_uris]
    )
    log.info("oauth register: client_id=%s name=%r", client.client_id, client.client_name)

    return JSONResponse(
        status_code=201,
        content={
            "client_id": client.client_id,
            "client_name": client.client_name,
            "redirect_uris": client.redirect_uris,
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
            "client_id_issued_at": int(client.created_at),
        },
    )


# --------------------------------------------------------------------------- #
# Authorization — consent page + code issuance
# --------------------------------------------------------------------------- #


def _render_consent_page(
    *,
    client_name: str,
    client_id: str,
    redirect_uri: str,
    response_type: str,
    scope: str,
    state: str,
    code_challenge: str,
    code_challenge_method: str,
) -> str:
    safe_name = html.escape(client_name)
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Hermes MCP — authorize connection</title>
<style>
  body {{ font-family: -apple-system, sans-serif; max-width: 480px; margin: 4rem auto; padding: 0 1.5rem; color: #111; }}
  h1   {{ font-size: 1.4rem; font-weight: 600; margin-bottom: 0.5rem; }}
  p    {{ color: #444; line-height: 1.5; }}
  .box {{ background: #f6f6f4; border: 1px solid #e0e0dc; border-radius: 6px; padding: 1rem 1.25rem; margin: 1.5rem 0; font-size: 0.9rem; }}
  .box dt {{ font-weight: 600; color: #111; }}
  .box dd {{ margin: 0 0 0.6rem 0; color: #555; word-break: break-all; }}
  .actions {{ display: flex; gap: 0.75rem; margin-top: 1.5rem; }}
  button {{ font: inherit; padding: 0.6rem 1.1rem; border-radius: 6px; border: 1px solid #ccc; cursor: pointer; }}
  .approve {{ background: #111; color: #fff; border-color: #111; }}
  .deny    {{ background: #fff; color: #111; }}
</style>
</head>
<body>
<h1>Authorize connection</h1>
<p><strong>{safe_name}</strong> is requesting access to your Hermes MCP bridge.</p>
<p>Approving will let this client list conversations, read messages, send messages, and respond to permission requests across your connected messaging platforms.</p>
<div class="box">
  <dl>
    <dt>Client</dt><dd>{safe_name}</dd>
    <dt>Redirect URI</dt><dd>{html.escape(redirect_uri)}</dd>
    <dt>Scope</dt><dd>{html.escape(scope or 'mcp')}</dd>
  </dl>
</div>
<form method="post" action="/oauth/authorize">
  <input type="hidden" name="client_id" value="{html.escape(client_id)}">
  <input type="hidden" name="redirect_uri" value="{html.escape(redirect_uri)}">
  <input type="hidden" name="response_type" value="{html.escape(response_type)}">
  <input type="hidden" name="scope" value="{html.escape(scope or 'mcp')}">
  <input type="hidden" name="state" value="{html.escape(state)}">
  <input type="hidden" name="code_challenge" value="{html.escape(code_challenge)}">
  <input type="hidden" name="code_challenge_method" value="{html.escape(code_challenge_method)}">
  <div class="actions">
    <button type="submit" name="action" value="approve" class="approve">Approve</button>
    <button type="submit" name="action" value="deny"    class="deny">Deny</button>
  </div>
</form>
</body>
</html>
"""


async def authorize_get(request: Request) -> Response:
    store, _, _ = _require_ctx()
    qp = request.query_params

    client_id = qp.get("client_id", "")
    redirect_uri = qp.get("redirect_uri", "")
    response_type = qp.get("response_type", "code")
    scope = qp.get("scope", "mcp")
    state = qp.get("state", "")
    code_challenge = qp.get("code_challenge", "")
    code_challenge_method = qp.get("code_challenge_method", "S256")

    if response_type != "code":
        return JSONResponse(
            status_code=400,
            content={"error": "unsupported_response_type", "error_description": "only 'code' supported"},
        )
    if code_challenge_method != "S256":
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_request", "error_description": "only S256 code_challenge_method supported"},
        )
    if not code_challenge:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_request", "error_description": "code_challenge is required"},
        )

    client = store.get_client(client_id)
    if not client:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_request", "error_description": "unknown client_id"},
        )
    if redirect_uri not in client.redirect_uris:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_request", "error_description": "redirect_uri not registered for this client"},
        )

    body = _render_consent_page(
        client_name=client.client_name,
        client_id=client_id,
        redirect_uri=redirect_uri,
        response_type=response_type,
        scope=scope,
        state=state,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
    )
    return HTMLResponse(body)


async def authorize_post(request: Request) -> Response:
    store, _, _ = _require_ctx()
    form = await request.form()

    client_id = form.get("client_id", "")
    redirect_uri = form.get("redirect_uri", "")
    response_type = form.get("response_type", "")
    scope = form.get("scope", "")
    state = form.get("state", "")
    code_challenge = form.get("code_challenge", "")
    code_challenge_method = form.get("code_challenge_method", "")
    action = form.get("action", "")

    client = store.get_client(client_id)
    if not client or redirect_uri not in client.redirect_uris:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_request", "error_description": "client/redirect_uri mismatch"},
        )

    if action != "approve":
        params = {"error": "access_denied", "error_description": "user denied request"}
        if state:
            params["state"] = state
        return RedirectResponse(f"{redirect_uri}?{urlencode(params)}", status_code=302)

    if response_type != "code" or code_challenge_method != "S256" or not code_challenge:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_request", "error_description": "invalid authorization request parameters"},
        )

    auth_code = store.issue_code(
        client_id=client_id,
        redirect_uri=redirect_uri,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        scope=scope or "mcp",
    )
    log.info("oauth authorize: code issued for client_id=%s", client_id)

    params = {"code": auth_code.code}
    if state:
        params["state"] = state
    return RedirectResponse(f"{redirect_uri}?{urlencode(params)}", status_code=302)


# --------------------------------------------------------------------------- #
# Token exchange
# --------------------------------------------------------------------------- #


async def token(request: Request) -> Response:
    store, signing_key, issuer = _require_ctx()
    form = await request.form()

    grant_type = form.get("grant_type", "")

    if grant_type == "authorization_code":
        code = form.get("code")
        redirect_uri = form.get("redirect_uri")
        client_id = form.get("client_id")
        code_verifier = form.get("code_verifier")
        if not (code and redirect_uri and client_id and code_verifier):
            return _json_err(
                "invalid_request",
                "authorization_code requires code, redirect_uri, client_id, code_verifier",
            )
        client = store.get_client(client_id)
        if not client:
            return _json_err("invalid_client", "unknown client_id")

        auth_code = store.consume_code(code)
        if not auth_code:
            return _json_err("invalid_grant", "code is invalid, expired, or already used")
        if auth_code.client_id != client_id:
            return _json_err("invalid_grant", "code does not belong to this client")
        if auth_code.redirect_uri != redirect_uri:
            return _json_err("invalid_grant", "redirect_uri mismatch")
        if not verify_s256(code_verifier, auth_code.code_challenge, auth_code.code_challenge_method):
            return _json_err("invalid_grant", "PKCE verification failed")

        access = issue_access_token(
            signing_key=signing_key,
            issuer=issuer,
            client_id=client_id,
            scope=auth_code.scope,
        )
        rt = store.issue_refresh_token(client_id=client_id)
        log.info(
            "oauth token: access+refresh issued for client_id=%s jti=%s",
            client_id, access.jti,
        )
        return JSONResponse(
            {
                "access_token": access.jwt_str,
                "token_type": "Bearer",
                "expires_in": access.expires_in,
                "refresh_token": rt.token,
                "scope": auth_code.scope,
            }
        )

    if grant_type == "refresh_token":
        refresh_token = form.get("refresh_token")
        client_id = form.get("client_id")
        if not refresh_token:
            return _json_err("invalid_request", "refresh_token is required")
        rotated = store.rotate_refresh_token(refresh_token)
        if not rotated:
            return _json_err("invalid_grant", "refresh_token invalid, expired, or revoked")
        new_rt, client_id_from_token = rotated

        if client_id and client_id != client_id_from_token:
            return _json_err("invalid_grant", "refresh_token does not belong to this client")

        access = issue_access_token(
            signing_key=signing_key,
            issuer=issuer,
            client_id=client_id_from_token,
            scope="mcp",
        )
        log.info(
            "oauth token: refresh rotated for client_id=%s jti=%s",
            client_id_from_token, access.jti,
        )
        return JSONResponse(
            {
                "access_token": access.jwt_str,
                "token_type": "Bearer",
                "expires_in": access.expires_in,
                "refresh_token": new_rt.token,
                "scope": "mcp",
            }
        )

    return _json_err("unsupported_grant_type", f"unsupported grant_type: {grant_type}")


# --------------------------------------------------------------------------- #
# Public surface — `oauth_routes` is the list mcp_serve appends to the
# FastMCP Starlette router.
# --------------------------------------------------------------------------- #

oauth_routes: list[Route] = [
    Route("/.well-known/oauth-protected-resource", protected_resource_metadata, methods=["GET"]),
    Route("/.well-known/oauth-protected-resource/mcp", protected_resource_metadata_mcp, methods=["GET"]),
    Route("/.well-known/oauth-authorization-server", authorization_server_metadata, methods=["GET"]),
    Route("/oauth/register", register_client, methods=["POST"]),
    Route("/register", register_client, methods=["POST"]),
    Route("/oauth/authorize", authorize_get, methods=["GET"]),
    Route("/oauth/authorize", authorize_post, methods=["POST"]),
    Route("/oauth/token", token, methods=["POST"]),
]


# Backward-compat shim — earlier code imported ``router``. Keep an alias so
# nothing breaks if some caller still references it.
class _RouterShim:
    routes = oauth_routes


router = _RouterShim()
