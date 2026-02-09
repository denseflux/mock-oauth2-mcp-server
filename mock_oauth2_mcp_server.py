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

import uuid
from typing import Any, Dict, Optional, Set

from fastapi import FastAPI, Form, Header, Request
from fastapi.responses import JSONResponse

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
TEST_CLIENT_ID = "test-client"
TEST_CLIENT_SECRET = "test-secret"

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

# ---------------------------------------------------------------------------
# App & state
# ---------------------------------------------------------------------------
app = FastAPI(title="Mock OAuth2 MCP Server")

# In-memory set of valid bearer tokens
_valid_tokens: Set[str] = set()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _jsonrpc_response(id: Any, result: Any) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": id, "result": result}


def _jsonrpc_error(id: Any, code: int, message: str) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}}


def _validate_bearer_token(authorization: Optional[str]) -> bool:
    """Return True if the Authorization header carries a valid bearer token."""
    if not authorization:
        return False
    parts = authorization.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return False
    return parts[1] in _valid_tokens


# ---------------------------------------------------------------------------
# OAuth2 token endpoint
# ---------------------------------------------------------------------------
@app.post("/oauth/token")
async def oauth_token(
    grant_type: str = Form(...),
    client_id: str = Form(...),
    client_secret: str = Form(...),
):
    if grant_type != "client_credentials":
        return JSONResponse(
            status_code=400,
            content={"error": "unsupported_grant_type"},
        )

    if client_id != TEST_CLIENT_ID or client_secret != TEST_CLIENT_SECRET:
        return JSONResponse(
            status_code=401,
            content={"error": "invalid_client"},
        )

    token = str(uuid.uuid4())
    _valid_tokens.add(token)

    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": 3600,
    }


# ---------------------------------------------------------------------------
# MCP Streamable HTTP endpoint
# ---------------------------------------------------------------------------
@app.post("/mcp")
async def mcp_endpoint(
    request: Request,
    authorization: Optional[str] = Header(None),
):
    # -- Auth check ----------------------------------------------------------
    if not _validate_bearer_token(authorization):
        return JSONResponse(
            status_code=401,
            content={"error": "invalid_or_missing_bearer_token"},
        )

    # -- Parse JSON-RPC body -------------------------------------------------
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

    # -- initialize ----------------------------------------------------------
    if method == "initialize":
        return JSONResponse(content=_jsonrpc_response(req_id, SERVER_INFO))

    # -- tools/list ----------------------------------------------------------
    if method == "tools/list":
        return JSONResponse(
            content=_jsonrpc_response(req_id, {"tools": [ECHO_TOOL]})
        )

    # -- tools/call ----------------------------------------------------------
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
                {
                    "content": [{"type": "text", "text": message}],
                },
            ),
        )

    # -- notifications (no response required) --------------------------------
    if method.startswith("notifications/"):
        return JSONResponse(content={}, status_code=202)

    # -- Unknown method ------------------------------------------------------
    return JSONResponse(
        content=_jsonrpc_error(req_id, -32601, f"Method not found: {method}")
    )


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8765)
