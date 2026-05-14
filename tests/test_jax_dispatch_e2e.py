"""End-to-end coverage for the jax-dispatch hook.

This test exercises the real hook entry point against an in-process
FastAPI app that behaves like Reid's internal dispatch poll endpoint.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI, Request


_REAL_HTTPX_ASYNC_CLIENT = httpx.AsyncClient
HOOK_DIR = Path.home() / ".hermes" / "hooks" / "jax-dispatch"
_HANDLER_SPEC = importlib.util.spec_from_file_location(
    "jax_dispatch_handler_e2e", HOOK_DIR / "handler.py"
)
assert _HANDLER_SPEC is not None
assert _HANDLER_SPEC.loader is not None
handler = importlib.util.module_from_spec(_HANDLER_SPEC)
sys.modules["jax_dispatch_handler_e2e"] = handler
_HANDLER_SPEC.loader.exec_module(handler)


class _InProcessAsyncClient:
    """httpx.AsyncClient shim backed by a FastAPI app."""

    def __init__(self, *args, app: FastAPI, timeout=None, **kwargs):
        self._client = _REAL_HTTPX_ASYNC_CLIENT(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
            timeout=timeout,
        )

    async def __aenter__(self):
        await self._client.__aenter__()
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return await self._client.__aexit__(exc_type, exc, tb)

    async def post(self, url, *, json=None, headers=None):
        return await self._client.post(url, json=json, headers=headers)


@pytest.fixture
def hermes_hook_env(tmp_path, monkeypatch):
    key_path = tmp_path / "internal-api-key"
    key_path.write_text("e2e-dispatch-key")
    state_dir = tmp_path / "state" / "jax-dispatch"

    monkeypatch.setattr(
        handler,
        "_load_config",
        lambda: {
            **handler._DEFAULTS,
            "reid_internal_url": "http://testserver",
            "reid_internal_key_path": str(key_path),
            "poll_limit": 10,
            "http_timeout_seconds": 0.5,
            "agent_identity": "jax",
        },
    )
    monkeypatch.setattr(handler, "_load_key", lambda path: key_path.read_text().strip())
    monkeypatch.setattr(handler, "_state_dir", lambda: state_dir)
    monkeypatch.setattr(handler, "_pending_state_path", lambda: state_dir / "pending.json")
    return {"key_path": key_path, "state_dir": state_dir}


@pytest.mark.asyncio
async def test_pre_llm_call_uses_in_process_reid_poll_endpoint(hermes_hook_env, monkeypatch):
    row = {
        "id": "22222222-2222-2222-2222-222222222222",
        "source": "reid",
        "target": "jax",
        "dispatch_kind": "dispatch",
        "priority": "high",
        "trust_level": "internal",
        "correlation_id": "reid-v8.5-surgical-2-resub-2026-05-14",
        "payload": {
            "subject": "Surgical 2 resubmission",
            "body": "Five-step operator work requires repo init, one e2e test, pytest, grep, and commit.",
            "needs": "reply",
        },
        "status": "read",
        "created_at": "2026-05-14T17:22:41.982700+00:00",
        "read_at": "2026-05-14T17:28:26.210113+00:00",
        "acked_at": None,
        "expires_at": "2026-05-21T17:22:41.982700+00:00",
        "reviewed_by": None,
        "error": None,
    }
    observed = {}
    app = FastAPI()

    @app.post("/internal/dispatch/poll")
    async def poll(request: Request):
        observed["path"] = request.url.path
        observed["method"] = request.method
        observed["headers"] = dict(request.headers)
        observed["body"] = await request.json()
        assert observed["headers"]["x-internal-key"] == "e2e-dispatch-key"
        assert observed["body"] == {"target": "jax", "status": "queued", "limit": 10}
        return {"dispatches": [row], "count": 1}

    monkeypatch.setattr(
        handler.httpx,
        "AsyncClient",
        lambda *a, **kw: _InProcessAsyncClient(app=app, timeout=kw.get("timeout")),
    )

    context: dict = {}
    result = await handler.handle("pre_llm_call", context)

    assert context == {}
    assert result == {"context": handler.format_dispatch_block([row])}
    assert observed["path"] == "/internal/dispatch/poll"
    assert observed["method"] == "POST"

    pending_path = hermes_hook_env["state_dir"] / "pending.json"
    assert pending_path.exists()
    pending = json.loads(pending_path.read_text())
    assert pending["rows"] == [
        {
            "id": row["id"],
            "source": row["source"],
            "dispatch_kind": row["dispatch_kind"],
            "priority": row["priority"],
            "correlation_id": row["correlation_id"],
            "payload": row["payload"],
        }
    ]
    assert "Inbox — agent_dispatch v1" in result["context"]
    assert row["correlation_id"] in result["context"]
    assert "Surgical 2 resubmission" in result["context"]
    assert "Five-step operator work" in result["context"]
