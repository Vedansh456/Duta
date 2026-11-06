
"""
Duta MCP server with embedded OAuth and explicit user consent.

For this initial prototype:
- The MCP SDK handles OAuth protocol routes and bearer-token validation.
- Duta's provider issues authorization codes and tokens.
- The consent page requires an explicit user decision.
- The workspace's existing filesystem permissions remain authoritative.
- The server binds to localhost; a secure HTTPS tunnel can expose it remotely.

OAuth state is currently held in memory. Do not treat this prototype
as production-ready until persistence, lifecycle, and security tests pass.
"""

from __future__ import annotations

import argparse
import html
import logging
import os
import time
from pathlib import Path
from urllib.parse import urlparse

import uvicorn
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.routing import Route

from duta.config import load_config
from duta.core import Duta, DutaError
from duta.oauth_provider import DutaOAuthProvider


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("duta")

_duta: Duta | None = None
_oauth: DutaOAuthProvider | None = None


def get_duta() -> Duta:
    """Return the configured filesystem bridge."""
    if _duta is None:
        raise RuntimeError("Duta has not been initialized.")
    return _duta


def get_oauth() -> DutaOAuthProvider:
    """Return the active OAuth provider."""
    if _oauth is None:
        raise RuntimeError("Duta OAuth has not been initialized.")
    return _oauth


# ---------------------------------------------------------------------------
# MCP tools
# ---------------------------------------------------------------------------

mcp = MCPServer(
    "Duta",
    version="0.1.0",
)


@mcp.tool()
def duta_list_files(max_entries: int = 500) -> str:
    """List files and directories visible under configured permissions."""
    entries = get_duta().tree(max_entries=max_entries)

    import json

    return json.dumps(
        [
            {
                "path": entry.path,
                "kind": entry.kind,
                "size_bytes": entry.size_bytes,
            }
            for entry in entries
        ],
        indent=2,
    )


@mcp.tool()
def duta_read_file(path: str) -> str:
    """Read an authorized UTF-8 text file."""
    return get_duta().read(path)


@mcp.tool()
def duta_create_file(path: str, content: str) -> str:
    """Create a file when Duta grants create permission."""
    get_duta().create(path, content)
    return f"Created file: {path}"


@mcp.tool()
def duta_edit_file(path: str, content: str) -> str:
    """Replace a file's contents when Duta grants edit permission."""
    get_duta().edit(path, content)
    return f"Updated file: {path}"


# ---------------------------------------------------------------------------
# Workspace initialization
# ---------------------------------------------------------------------------

def initialize_workspace(workspace: Path) -> None:
    """Load the workspace and its configured permission rules."""
    global _duta

    workspace = workspace.expanduser().resolve(strict=True)

    if not workspace.is_dir():
        raise ValueError("Workspace must be a directory.")

    config_file = workspace / ".duta" / "config.json"

    if not config_file.is_file():
        raise FileNotFoundError(
            f"No Duta configuration found at {config_file}. "
            "Initialize the workspace and configure permissions first."
        )

    config = load_config(workspace)
    instance = Duta(workspace)

    for rule in config["permissions"]:
        instance.allow(
            rule["pattern"],
            permissions=tuple(rule["permissions"]),
        )

    _duta = instance


# ---------------------------------------------------------------------------
# Consent page
# ---------------------------------------------------------------------------

def render_consent_page(
    request_id: str,
    csrf_token: str,
    client_name: str,
) -> str:
    """Render a consent page with escaped values and explicit choices."""
    safe_request_id = html.escape(request_id, quote=True)
    safe_csrf_token = html.escape(csrf_token, quote=True)
    safe_client_name = html.escape(client_name)

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Authorize Duta connection</title>
  <style>
    body {{
      font-family: system-ui, sans-serif;
      max-width: 620px;
      margin: 60px auto;
      padding: 0 20px;
      line-height: 1.6;
      color: #18202a;
    }}
    .card {{
      border: 1px solid #d6dce5;
      border-radius: 14px;
      padding: 28px;
    }}
    button {{
      padding: 12px 18px;
      border-radius: 8px;
      border: 0;
      cursor: pointer;
      font-size: 1rem;
      margin: 12px 8px 0 0;
    }}
    .approve {{ background: #176b45; color: white; }}
    .deny {{ background: #e8edf3; color: #18202a; }}
    .warning {{ background: #fff5d8; padding: 12px; border-radius: 8px; }}
  </style>
</head>
<body>
  <main class="card">
    <h1>Authorize Duta</h1>
    <p><strong>{safe_client_name}</strong> is requesting access to Duta.</p>

    <div class="warning">
      Approval permits the application to use Duta's available filesystem
      tools. Your configured Duta file permissions still apply.
    </div>

    <p>Only approve this request if you initiated the connection and
       recognize the application.</p>

    <form method="post" action="/oauth/decision">
      <input type="hidden" name="request_id" value="{safe_request_id}">
      <input type="hidden" name="csrf_token" value="{safe_csrf_token}">
      <button class="approve" type="submit" name="decision" value="approve">
        Approve connection
      </button>
      <button class="deny" type="submit" name="decision" value="deny">
        Deny
      </button>
    </form>
  </main>
</body>
</html>"""


async def consent_page(request: Request) -> HTMLResponse:
    """Show the consent screen for a pending OAuth request."""
    request_id = request.query_params.get("request_id", "")

    try:
        pending = get_oauth().get_pending_request(request_id)
    except ValueError:
        return HTMLResponse(
            "<h1>Authorization request expired</h1>"
            "<p>Return to your AI client and start connecting again.</p>",
            status_code=400,
        )

    client = await get_oauth().get_client(pending["client_id"])
    client_name = (
        client.client_name
        if client and client.client_name
        else pending["client_id"]
    )

    return HTMLResponse(
        render_consent_page(
            request_id,
            pending["csrf_token"],
            client_name,
        ),
        headers={"Cache-Control": "no-store"},
    )


async def consent_decision(request: Request):
    """Validate consent and log the exact reason for rejection."""
    public_url = os.environ.get("DUTA_PUBLIC_URL", "").rstrip("/")
    origin = request.headers.get("origin", "").rstrip("/")

    if not public_url or origin != public_url:
        logger.warning("OAuth consent rejected: origin mismatch.")
        return HTMLResponse(
            "<h1>Request rejected</h1>"
            "<p>The consent submission did not come from Duta's origin.</p>",
            status_code=403,
            headers={"Cache-Control": "no-store"},
        )

    try:
        form = await request.form()
        request_id = str(form.get("request_id", ""))
        csrf_token = str(form.get("csrf_token", ""))
        decision = str(form.get("decision", ""))

        provider = get_oauth()

        # Log presence only. Never log the request ID or CSRF token.
        logger.info(
            "OAuth consent submission: request_id_present=%s, "
            "csrf_present=%s, decision=%s, pending_count=%d",
            bool(request_id),
            bool(csrf_token),
            decision,
            len(provider.pending),
        )

        pending = provider.pending.get(request_id)

        if pending is None:
            logger.warning("OAuth consent rejected: pending request not found.")
            raise ValueError(
                "Consent request is no longer available. Start a fresh authorization."
            )

        if pending["expires_at"] <= time.time():
            logger.warning("OAuth consent rejected: pending request expired.")
            raise ValueError(
                "Consent request expired. Start a fresh authorization."
            )

        if not provider.verify_csrf_token(request_id, csrf_token):
            logger.warning(
                "OAuth consent rejected: CSRF verification failed "
                "(request exists and has not expired)."
            )
            raise ValueError("Consent verification failed. Start a fresh authorization.")

        if decision == "approve":
            redirect_url = provider.approve_request(request_id, csrf_token)
        elif decision == "deny":
            redirect_url = provider.reject_request(request_id, csrf_token)
        else:
            raise ValueError("Invalid consent decision.")

        parsed = urlparse(redirect_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("Invalid client redirect URL.")

        return RedirectResponse(
            redirect_url,
            status_code=303,
            headers={"Cache-Control": "no-store"},
        )

    except ValueError as exc:
        logger.warning("OAuth consent rejected: %s", exc)
        return HTMLResponse(
            f"<h1>Authorization failed</h1><p>{html.escape(str(exc))}</p>",
            status_code=400,
            headers={"Cache-Control": "no-store"},
        )


# ---------------------------------------------------------------------------
# Root-level OAuth protected-resource metadata
# ---------------------------------------------------------------------------

async def protected_resource_metadata_root(
    request: Request,
) -> JSONResponse:
    """
    Expose protected-resource metadata at the root discovery URL.

    The MCP SDK also exposes the path-specific metadata URL for /mcp.
    Some OAuth clients request the root well-known URL, so publish the same
    resource metadata there as well.
    """
    public_url = os.environ.get("DUTA_PUBLIC_URL", "").rstrip("/")

    if not public_url:
        return JSONResponse(
            {"error": "DUTA_PUBLIC_URL is not configured."},
            status_code=503,
            headers={
                "Cache-Control": "no-store",
                "Access-Control-Allow-Origin": "*",
            },
        )

    metadata = {
        "resource": f"{public_url}/mcp",
        "authorization_servers": [public_url],
        "scopes_supported": ["duta:access"],
        "bearer_methods_supported": ["header"],
    }

    return JSONResponse(
        metadata,
        headers={
            "Access-Control-Allow-Origin": "*",
            "Cache-Control": "public, max-age=3600",
        },
    )


# ---------------------------------------------------------------------------
# Server startup
# ---------------------------------------------------------------------------

def main() -> None:
    global _oauth, mcp

    parser = argparse.ArgumentParser(description="Run the Duta MCP server.")
    parser.add_argument("--workspace", required=True)
    parser.add_argument(
        "--transport",
        choices=("stdio", "streamable-http"),
        default="stdio",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()

    try:
        initialize_workspace(Path(args.workspace))
    except (DutaError, OSError, ValueError, KeyError, TypeError) as exc:
        logger.error("Duta startup failed: %s", exc)
        raise SystemExit(1) from exc

    if args.transport == "stdio":
        mcp.run(transport="stdio")
        return

    if args.host not in {"127.0.0.1", "localhost", "::1"}:
        logger.error("Only localhost binding is permitted.")
        raise SystemExit(1)

    if not 1 <= args.port <= 65535:
        logger.error("Port must be between 1 and 65535.")
        raise SystemExit(1)

    public_url = os.environ.get("DUTA_PUBLIC_URL", "").rstrip("/")

    if not public_url.startswith("https://"):
        logger.error(
            "Set DUTA_PUBLIC_URL to the public HTTPS base URL "
            "before starting the OAuth HTTP server."
        )
        raise SystemExit(1)

    parsed_public_url = urlparse(public_url)

    if not parsed_public_url.netloc or parsed_public_url.path not in {"", "/"}:
        logger.error("DUTA_PUBLIC_URL must be a base URL without a path.")
        raise SystemExit(1)

    _oauth = DutaOAuthProvider(public_url=public_url)

    auth_settings = AuthSettings(
        # Public HTTPS URL used as Duta's OAuth issuer.
        issuer_url=public_url,

        # MCP resource that the access tokens are intended for.
        resource_server_url=f"{public_url}/mcp",

        # Require authorization for Duta's filesystem tools.
        required_scopes=["duta:access"],

        # Reject tokens issued for a different resource.
        validate_token_resource=True,

        # Enable the SDK's standard dynamic OAuth client-registration flow.
        client_registration_options=ClientRegistrationOptions(
            enabled=True,
            valid_scopes=["duta:access"],
            default_scopes=["duta:access"],
        ),
    )

    # Recreate the MCP server with the embedded OAuth provider.
    mcp = MCPServer(
        "Duta",
        version="0.1.0",
        auth=auth_settings,
        auth_server_provider=_oauth,
    )

    # Register the same tools on the authenticated MCP server.
    # These functions still enforce Duta's workspace permissions.
    mcp.tool()(duta_list_files)
    mcp.tool()(duta_read_file)
    mcp.tool()(duta_create_file)
    mcp.tool()(duta_edit_file)

    # Allow only local hosts and the current Cloudflare tunnel hostname.
    # DNS rebinding protection remains enabled.
    allowed_hosts = [
        "127.0.0.1:*",
        "localhost:*",
        "[::1]:*",
        parsed_public_url.hostname,
    ]

    allowed_origins = [
        "http://127.0.0.1:*",
        "http://localhost:*",
        "http://[::1]:*",
        public_url,
    ]

    transport_security = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=allowed_hosts,
        allowed_origins=allowed_origins,
    )

    app = mcp.streamable_http_app(
        transport_security=transport_security,
        host=args.host,
    )

    # Add a root-level protected-resource metadata alias for OAuth clients
    # that discover /.well-known/oauth-protected-resource without /mcp.
    app.routes.append(
        Route(
            "/.well-known/oauth-protected-resource",
            protected_resource_metadata_root,
            methods=["GET"],
        )
    )

    # Add the consent routes to the same application as the SDK's OAuth routes.
    app.routes.append(Route("/oauth/consent", consent_page, methods=["GET"]))
    app.routes.append(
        Route("/oauth/decision", consent_decision, methods=["POST"])
    )

    logger.info("Starting Duta OAuth-enabled MCP server.")
    logger.info("Local MCP endpoint: http://%s:%s/mcp", args.host, args.port)
    logger.info("OAuth issuer: %s", public_url)

    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
