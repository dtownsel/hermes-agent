"""OAuth 2.1 + PKCE layer for the Hermes MCP server.

Ported from reid-v7's app/auth/ (single-user, file-backed JSON state).
Hermes uses this to let claude.ai's MCP connector pair with the local
``hermes mcp serve --transport http`` endpoint without a static bearer
token (which claude.ai's UI doesn't support).

  * ``store``       — file-backed JSON state (clients, codes, refresh tokens)
  * ``pkce``        — S256 code-challenge verification
  * ``jwt_tokens``  — HS256 access token issuance and validation (PyJWT)
  * ``middleware``  — Bearer guard for /mcp/* (401 + WWW-Authenticate)
  * ``endpoints``   — APIRouter exposing /oauth/* and /.well-known/*

Single-user, single-process. No DB tables, no Redis, no Celery. All
secrets live under ~/.config/hermes-mcp/ with mode 0600.
"""
