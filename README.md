# Mock OAuth2 MCP Server

A lightweight mock server that combines an OAuth2 token endpoint with an MCP (Model Context Protocol) Streamable HTTP endpoint. Built for testing OAuth2 client_credentials (M2M) flows with LiteLLM proxy.

## Features

- **OAuth2 token endpoint** (`POST /oauth/token`) — issues bearer tokens via the `client_credentials` grant
- **MCP endpoint** (`POST /mcp`) — Streamable HTTP transport with a built-in `echo` tool
- **Bearer token validation** — the MCP endpoint rejects requests without a valid token

## Quick Start

```bash
pip install fastapi uvicorn
```

```bash
python mock_oauth2_mcp_server.py
```

The server starts on **port 8765**.

### Test Credentials

| Parameter       | Value           |
|-----------------|-----------------|
| `client_id`     | `test-client`   |
| `client_secret` | `test-secret`   |

## LiteLLM Config

Add the following to your LiteLLM proxy config YAML:

```yaml
mcp_servers:
  test_oauth2_server:
    url: "http://localhost:8765/mcp"
    transport: "http"
    auth_type: "oauth2"
    client_id: "test-client"
    client_secret: "test-secret"
    token_url: "http://localhost:8765/oauth/token"
```

## Documentation

See the full LiteLLM MCP OAuth docs: https://docs.litellm.ai/docs/mcp_oauth
