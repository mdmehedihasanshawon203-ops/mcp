"""`phone-harness-mcp`: stdio for a local client, `--port` for a hosted server.

    uvx phone-harness-mcp                      # stdio; signs in as this machine
    phone-harness-mcp --port 8000              # streamable HTTP at /mcp; each
                                               # request brings its own bearer

Over stdio the server uses this machine's credential: PHONE_HARNESS_API_KEY,
`--api-key`, or the sign-in from `phone-harness cloud login`. Over HTTP it
uses none of those, ever: the bearer on each request is forwarded to Phone
Harness Cloud, so one process can serve many accounts and leaks none.
"""
from __future__ import annotations

import sys

import click

from . import __version__
from .cloud import API_URL, api_url, local_credentials
from .server import build_server, hosted_cloud, stdio_cloud


def _security(host: str, allowed_hosts: str | None, allowed_origins: str | None):
    """Host-header policy for HTTP mode (DNS-rebinding protection), or None for the SDK's default."""
    from mcp.server.transport_security import TransportSecuritySettings
    if allowed_hosts is None:
        if host not in ("127.0.0.1", "localhost", "::1"):
            click.echo(f"phone-harness-mcp: listening on {host} without --allowed-hosts; the Host header is not "
                       "checked. Behind a reverse proxy pass --allowed-hosts <public hostname>.", err=True)
        return None
    hosts = [h.strip() for h in allowed_hosts.split(",") if h.strip()]
    if hosts == ["*"]:
        return TransportSecuritySettings(enable_dns_rebinding_protection=False)
    origins = [o.strip() for o in (allowed_origins or "").split(",") if o.strip()]
    if not origins:
        for h in hosts:
            base = h[:-2] if h.endswith(":*") else h
            origins += [f"https://{base}", f"http://{base}"]
    return TransportSecuritySettings(enable_dns_rebinding_protection=True, allowed_hosts=hosts,
                                     allowed_origins=origins)


DEFAULT_OAUTH_SCOPE = "phone:drive"


def build_http_app(*, api: str | None, mcp_path: str, host: str, allowed_hosts: str | None,
                   allowed_origins: str | None, public_url: str | None, oauth_issuer: str | None,
                   stateful: bool, oauth_scope: str | None = DEFAULT_OAUTH_SCOPE):
    """The ASGI app for `--port`. Separate from `main` so tests can serve it."""
    from starlette.requests import Request
    from starlette.responses import JSONResponse, HTMLResponse

    auth = token_verifier = None
    if oauth_issuer:
        if not public_url:
            raise click.UsageError("--oauth-issuer needs --public-url, the URL clients reach this server at.")
        from mcp.server.auth.settings import AuthSettings
        from .auth import CloudTokenVerifier
        # The scope is advertised in the protected-resource metadata, so a client
        # asks the authorization server for it; the API refuses a dynamic client's
        # token without it, and the verifier reports it for every bearer the API
        # accepts, API keys included.
        scopes = [oauth_scope] if oauth_scope else []
        auth = AuthSettings(issuer_url=oauth_issuer, resource_server_url=public_url,
                            validate_token_resource=False, required_scopes=scopes)
        token_verifier = CloudTokenVerifier(api, scopes=scopes)
    server = build_server(cloud_for=hosted_cloud(api), allow_files=False, auth=auth, token_verifier=token_verifier)

    @server.custom_route("/health", methods=["GET"])
    async def health(request: Request):
        return JSONResponse({"ok": True, "version": __version__})

    @server.custom_route("/", methods=["GET"])
    async def index(request: Request):
        # Return HTML for browsers, JSON for API clients
        accept = request.headers.get("accept", "")
        if "text/html" in accept:
            html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Phone Harness MCP Server</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 2rem;
            line-height: 1.6;
            color: #333;
        }}
        h1 {{
            color: #000;
            border-bottom: 2px solid #000;
            padding-bottom: 0.5rem;
        }}
        .info {{
            background: #f5f5f5;
            padding: 1rem;
            border-radius: 4px;
            margin: 1rem 0;
        }}
        .info-item {{
            margin: 0.5rem 0;
        }}
        .label {{
            font-weight: 600;
            display: inline-block;
            width: 120px;
        }}
        a {{
            color: #0070f3;
            text-decoration: none;
        }}
        a:hover {{
            text-decoration: underline;
        }}
        .description {{
            margin: 1.5rem 0;
        }}
    </style>
    <script>
        window.si = window.si || function () {{ (window.siq = window.siq || []).push(arguments); }};
    </script>
    <script defer src="/_vercel/speed-insights/script.js"></script>
</head>
<body>
    <h1>Phone Harness MCP Server 🔌</h1>
    
    <div class="description">
        <p>Give any MCP agent a real iPhone or an Android emulator in the cloud.</p>
        <p>This server provides MCP (Model Context Protocol) tools to control real phones and emulators.</p>
    </div>
    
    <div class="info">
        <div class="info-item">
            <span class="label">Service:</span>
            <span>phone-harness</span>
        </div>
        <div class="info-item">
            <span class="label">Version:</span>
            <span>{__version__}</span>
        </div>
        <div class="info-item">
            <span class="label">MCP Endpoint:</span>
            <span><code>{mcp_path}</code></span>
        </div>
        <div class="info-item">
            <span class="label">Documentation:</span>
            <span><a href="https://github.com/phone-harness/mcp" target="_blank">GitHub Repository</a></span>
        </div>
        <div class="info-item">
            <span class="label">Website:</span>
            <span><a href="https://phone-harness.com" target="_blank">phone-harness.com</a></span>
        </div>
    </div>
    
    <h2>Setup</h2>
    <p>To use this server, add it as a custom connector in your MCP client:</p>
    <p><code>https://mcp.phone-harness.com/mcp</code></p>
    
    <p>For detailed setup instructions for Claude, Cursor, ChatGPT, and other clients, see the <a href="https://github.com/phone-harness/mcp" target="_blank">documentation</a>.</p>
</body>
</html>"""
            return HTMLResponse(html_content)
        else:
            return JSONResponse({"name": "phone-harness", "version": __version__, "mcp": mcp_path,
                                 "docs": "https://github.com/phone-harness/mcp"})

    app = server.streamable_http_app(streamable_http_path=mcp_path, json_response=True, stateless_http=not stateful,
                                     transport_security=_security(host, allowed_hosts, allowed_origins), host=host)
    if not oauth_issuer:
        from .auth import RequireBearer
        app = RequireBearer(app, mcp_path)
    return app


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="phone-harness-mcp")
@click.option("--api-key", metavar="KEY",
              help="Phone Harness API key (pck_…). Default: $PHONE_HARNESS_API_KEY, else the sign-in from "
                   "`phone-harness cloud login`. stdio mode only.")
@click.option("--api-url", metavar="URL", default=None,
              help=f"Phone Harness Cloud API. Default: $PHONE_HARNESS_CLOUD_API or {API_URL}.")
@click.option("--port", type=int, metavar="PORT",
              help="Serve streamable HTTP on this port instead of stdio. Every request must then carry its own "
                   "Authorization: Bearer header; this machine's credential is not used.")
@click.option("--host", default="127.0.0.1", show_default=True, help="Interface to bind in HTTP mode.")
@click.option("--path", "mcp_path", default="/mcp", show_default=True, help="URL path of the MCP endpoint.")
@click.option("--allowed-hosts", metavar="HOSTS",
              help="Host header values to accept, comma separated (host, host:port or host:*); '*' disables the "
                   "check. Default: loopback only when bound to loopback.")
@click.option("--allowed-origins", metavar="ORIGINS", help="Origin header values to accept, comma separated.")
@click.option("--public-url", metavar="URL", help="The URL clients reach this server at, e.g. "
              "https://mcp.phone-harness.com/mcp. Required with --oauth-issuer.")
@click.option("--oauth-issuer", metavar="URL",
              help="Publish OAuth protected-resource metadata naming this authorization server, and accept its "
                   "tokens (verified through the API). Without it, HTTP mode takes API keys only.")
@click.option("--oauth-scope", metavar="SCOPE", default=DEFAULT_OAUTH_SCOPE, show_default=True,
              help="The scope the protected-resource metadata advertises, which OAuth clients then request.")
@click.option("--stateful", is_flag=True, help="HTTP mode: keep one MCP session per client instead of answering "
              "each request on its own.")
def main(api_key, api_url, port, host, mcp_path, allowed_hosts, allowed_origins, public_url, oauth_issuer,
         oauth_scope, stateful):
    """MCP server for Phone Harness Cloud: drive a real iPhone or an Android emulator from any MCP client."""
    api = (api_url or globals()["api_url"]()).rstrip("/")
    if port is None:
        server = build_server(cloud_for=stdio_cloud(local_credentials(api_key), api), allow_files=True)
        server.run("stdio")
        return
    if api_key:
        click.echo("phone-harness-mcp: --api-key is ignored with --port; each request carries its own bearer.", err=True)
    import uvicorn
    app = build_http_app(api=api, mcp_path=mcp_path, host=host, allowed_hosts=allowed_hosts,
                         allowed_origins=allowed_origins, public_url=public_url, oauth_issuer=oauth_issuer,
                         stateful=stateful, oauth_scope=oauth_scope)
    click.echo(f"phone-harness-mcp {__version__}: http://{host}:{port}{mcp_path} -> {api}", err=True)
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":   # pragma: no cover
    sys.exit(main())
