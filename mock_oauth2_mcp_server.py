"""
Mock OAuth2 + MCP Server for E2E Testing

A combined OAuth2 authorization server and MCP (Streamable HTTP) server
for testing LiteLLM's OAuth2 client_credentials flow with MCP backends.

Hardcoded test credentials:
    client_id:     test-client
    client_secret: test-secret

Usage:
    python mock_oauth2_mcp_server.py          # starts on port 8765

LiteLLM proxy config example:

    mcp_servers:
      test_oauth2_server:
        url: "http://localhost:8765/mcp"
        transport: "http"
        auth_type: "oauth2"
        client_id: "test-client"
        client_secret: "test-secret"
        token_url: "http://localhost:8765/oauth/token"
"""

import os
import uuid
from typing import Any, Dict, Optional, Set
from urllib.parse import urlencode

from fastapi import FastAPI, Form, Header, Request, Query
from fastapi.responses import JSONResponse, RedirectResponse

# ---------------------------------------------------------------------------
# Configuration (Railway / env vars)
# ---------------------------------------------------------------------------
CLIENT_ID = os.getenv("CLIENT_ID", "test-client")
CLIENT_SECRET = os.getenv("CLIENT_SECRET", "test-secret")
PORT = int(os.getenv("PORT", "8765"))
HOST = os.getenv("HOST", "0.0.0.0")

# Public base URL of this service (set this on Railway!)
# Example: https://your-service.up.railway.app
BASE_URL = os.getenv("BASE_URL", f"http://localhost:{PORT}").rstrip("/")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SERVER_INFO = {
    "protocolVersion": "2025-03-26",
    "capabilities": {"tools": {}},
    "serverInfo": {
        "name": "mock-oauth2-mcp-server",
        "version": "0.1.0",
    },
}

ECHO_TOOL = {
    "name": "echo",
    "description": "Echoes back the provided message",
    "inputSchema": {
        "type": "object",
        "properties": {
            "message": {
                "type": "string",
                "description": "The message to echo back",
            }
        },
        "required": ["message"],
    },
}

app = FastAPI(title="Mock OAuth2 MCP Server (Grok compatible)")

# In-memory stores
_valid_tokens: Set[str] = set()
_auth_codes: Dict[str, dict] = {}          # code → {client_id, redirect_uri, ...}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _jsonrpc_response(id: Any, result: Any) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": id, "result": result}


def _jsonrpc_error(id: Any, code: int, message: str) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}}


def _validate_bearer_token(authorization: Optional[str]) -> bool:
    if not authorization:
        return False
    parts = authorization.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return False
    return parts[1] in _valid_tokens


# ---------------------------------------------------------------------------
# Discovery endpoints (what Grok looks for first)
# ---------------------------------------------------------------------------
@app.get("/.well-known/oauth-protected-resource")
async def protected_resource_metadata():
    return {
        "resource": f"{BASE_URL}/mcp",
        "authorization_servers": [BASE_URL],
        "scopes_supported": ["openid", "offline_access", "account"],
        "bearer_methods_supported": ["header"],
    }


@app.get("/.well-known/oauth-authorization-server")
@app.get("/.well-known/openid-configuration")
async def authorization_server_metadata():
    return {
        "issuer": BASE_URL,
        "authorization_endpoint": f"{BASE_URL}/oauth/authorize",
        "token_endpoint": f"{BASE_URL}/oauth/token",
        "registration_endpoint": f"{BASE_URL}/register",          # optional stub
        "scopes_supported": ["openid", "offline_access", "account"],
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "client_credentials"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "none"],
        "code_challenge_methods_supported": ["S256", "plain"],
    }


# ---------------------------------------------------------------------------
# Minimal Dynamic Client Registration (Grok sometimes calls this)
# ---------------------------------------------------------------------------
@app.post("/register")
async def register_client(request: Request):
    # Just accept anything and return the same client_id/secret
    return {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "client_id_issued_at": 0,
        "client_secret_expires_at": 0,
    }


# ---------------------------------------------------------------------------
# Authorization endpoint (Authorization Code + PKCE)
# ---------------------------------------------------------------------------
@app.get("oauth/authorize")
async def authorize(
    response_type: str = Query(...),
    client_id: str = Query(...),
    redirect_uri: str = Query(...),
    scope: str = Query(""),
    state: str = Query(""),
    code_challenge: str = Query(None),
    code_challenge_method: str = Query(None),
):
    if response_type != "code":
        return JSONResponse(status_code=400, content={"error": "unsupported_response_type"})

    # Issue a one-time authorization code
    code = str(uuid.uuid4())
    _auth_codes[code] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
    }

    # Redirect back to Grok with the code
    params = {"code": code}
    if state:
        params["state"] = state

    return RedirectResponse(f"{redirect_uri}?{urlencode(params)}")


# ---------------------------------------------------------------------------
# Token endpoint (supports both authorization_code and client_credentials)
# ---------------------------------------------------------------------------
@app.post("/oauth/token")
async def oauth_token(
    grant_type: str = Form(...),
    client_id: str = Form(None),
    client_secret: str = Form(None),
    code: str = Form(None),
    redirect_uri: str = Form(None),
    code_verifier: str = Form(None),
):
    # ----- client_credentials (original behaviour) -----
    if grant_type == "client_credentials":
        if client_id != CLIENT_ID or client_secret != CLIENT_SECRET:
            return JSONResponse(status_code=401, content={"error": "invalid_client"})
        token = str(uuid.uuid4())
        _valid_tokens.add(token)
        return {
            "access_token": token,
            "token_type": "bearer",
            "expires_in": 3600,
            "scope": "openid offline_access account",
        }

    # ----- authorization_code (what Grok uses) -----
    if grant_type == "authorization_code":
        if not code or code not in _auth_codes:
            return JSONResponse(status_code=400, content={"error": "invalid_grant"})

        stored = _auth_codes.pop(code)  # one-time use

        # Very loose checks – enough for a personal mock
        if redirect_uri and stored["redirect_uri"] != redirect_uri:
            return JSONResponse(status_code=400, content={"error": "invalid_grant"})

        token = str(uuid.uuid4())
        _valid_tokens.add(token)

        return {
            "access_token": token,
            "token_type": "bearer",
            "expires_in": 3600,
            "scope": stored.get("scope") or "openid offline_access account",
            "refresh_token": str(uuid.uuid4()),   # optional but nice
        }

    return JSONResponse(status_code=400, content={"error": "unsupported_grant_type"})


# ---------------------------------------------------------------------------
# MCP Streamable HTTP endpoint
# ---------------------------------------------------------------------------
@app.post("/mcp")
async def mcp_endpoint(
    request: Request,
    authorization: Optional[str] = Header(None),
):
    if not _validate_bearer_token(authorization):
        return JSONResponse(
            status_code=401,
            content={"error": "invalid_or_missing_bearer_token"},
        )

    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            status_code=400,
            content=_jsonrpc_error(None, -32700, "Parse error"),
        )

    req_id = body.get("id")
    method = body.get("method", "")
    params = body.get("params", {})

    if method == "initialize":
        return JSONResponse(content=_jsonrpc_response(req_id, SERVER_INFO))

    if method == "tools/list":
        return JSONResponse(
            content=_jsonrpc_response(req_id, {"tools": [ECHO_TOOL]})
        )

    if method == "tools/call":
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})

        if tool_name != "echo":
            return JSONResponse(
                content=_jsonrpc_error(req_id, -32602, f"Unknown tool: {tool_name}")
            )

        message = arguments.get("message", "")
        return JSONResponse(
            content=_jsonrpc_response(
                req_id,
                {"content": [{"type": "text", "text": message}]},
            ),
        )

    if method.startswith("notifications/"):
        return JSONResponse(content={}, status_code=202)

    return JSONResponse(
        content=_jsonrpc_error(req_id, -32601, f"Method not found: {method}")
    )


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=HOST, port=PORT)