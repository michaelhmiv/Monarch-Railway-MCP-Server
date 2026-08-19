"""Small authenticated web wrapper for the Railway deployment.

The MCP server is still available at ``/mcp``.  This wrapper adds:

* a setup page protected by ``MONARCH_MCP_ACCESS_CODE``;
* browser-based Monarch login forms (password, browser cookies, and token);
* a signed, short-lived browser cookie for the setup page; and
* bearer-token protection for MCP clients that can send a custom header.

This is intentionally a single-user deployment model: one Railway service
stores one Monarch session.  It is not a multi-tenant proxy.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import html
import logging
import os
import secrets
import time
from typing import Any
from urllib.parse import urlencode

import uvicorn
from monarchmoney import CaptchaRequiredException, RequireMFAException
from starlette.applications import Starlette
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from starlette.routing import Route

from monarch_mcp_server.app import configure_tool_metadata, mcp
from monarch_mcp_server.monarch_auth import (
    EmailOtpRequiredException,
    login_with_browser_cookies,
    login_with_current_auth,
)
from monarch_mcp_server.secure_session import secure_session
from monarch_mcp_server.tool_metadata import tool_catalog

logger = logging.getLogger(__name__)

# ``web.py`` is the production entry point and is imported only after the app
# and all tool modules are loaded, so this is the safe point to finalize the
# complete metadata catalog.
configure_tool_metadata()

_ACCESS_ENV = "MONARCH_MCP_ACCESS_CODE"
_COOKIE_NAME = "monarch_mcp_session"
_COOKIE_TTL_SECONDS = 24 * 60 * 60
_OAUTH_CODE_TTL_SECONDS = 5 * 60
_OAUTH_TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60

# OAuth state is intentionally in memory. This is a single-user deployment,
# and a restart invalidates outstanding OAuth codes/tokens so the client must
# authorize again. Monarch's own session remains in secure_session storage.
_oauth_clients: dict[str, set[str]] = {}
_oauth_codes: dict[str, dict[str, Any]] = {}
_oauth_tokens: dict[str, float] = {}


def _access_code() -> str:
    return os.getenv(_ACCESS_ENV, "").strip()


def _external_base_url(request: Request) -> str:
    """Build the public URL when Railway terminates TLS at its proxy."""
    forwarded_proto = request.headers.get("x-forwarded-proto", "").split(",")[0].strip()
    forwarded_host = request.headers.get("x-forwarded-host", "").split(",")[0].strip()
    scheme = forwarded_proto or request.url.scheme
    host = forwarded_host or request.headers.get("host", request.url.netloc)
    return f"{scheme}://{host}".rstrip("/")


def _sign(value: str) -> str:
    return hmac.new(
        _access_code().encode("utf-8"), value.encode("utf-8"), hashlib.sha256
    ).hexdigest()


def _make_session_cookie() -> str:
    expires = str(int(time.time()) + _COOKIE_TTL_SECONDS)
    payload = f"{expires}.{secrets.token_urlsafe(12)}"
    return f"{payload}.{_sign(payload)}"


def _valid_session_cookie(value: str | None) -> bool:
    if not value or not _access_code():
        return False
    try:
        expires, nonce, signature = value.split(".", 2)
        payload = f"{expires}.{nonce}"
        return (
            int(expires) >= int(time.time())
            and hmac.compare_digest(signature, _sign(payload))
        )
    except (TypeError, ValueError):
        return False


def _has_access(request: Request) -> bool:
    if not _access_code():
        return False
    if _valid_session_cookie(request.cookies.get(_COOKIE_NAME)):
        return True
    authorization = request.headers.get("authorization", "")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer":
        return False
    token = token.strip()
    if hmac.compare_digest(token, _access_code()):
        return True
    expires_at = _oauth_tokens.get(token)
    if expires_at is None:
        return False
    if expires_at <= time.time():
        _oauth_tokens.pop(token, None)
        return False
    return True


class MCPAccessMiddleware(BaseHTTPMiddleware):
    """Protect the MCP route while leaving the setup UI public."""

    async def dispatch(self, request: Request, call_next: Any) -> Any:
        if request.url.path.rstrip("/") == "/mcp" and not _has_access(request):
            if not _access_code():
                return PlainTextResponse(
                    f"Set {_ACCESS_ENV} before using the MCP endpoint.",
                    status_code=503,
                )
            return PlainTextResponse(
                "MCP access required. Unlock the setup page or send "
                "Authorization: Bearer <OAuth access token>.",
                status_code=401,
                headers={
                    "WWW-Authenticate": (
                        'Bearer resource_metadata="'
                        f"{_external_base_url(request)}/.well-known/"
                        'oauth-protected-resource"'
                    )
                },
            )
        return await call_next(request)


def _page(title: str, body: str, *, message: str = "") -> HTMLResponse:
    notice = f'<div class="notice">{html.escape(message)}</div>' if message else ""
    return HTMLResponse(
        f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title>
<style>
:root {{ color-scheme: dark; --bg:#0c111d; --card:#151d2d; --ink:#eef2ff; --muted:#a9b3ca; --accent:#8ce0c1; --danger:#ff9f9f; }}
* {{ box-sizing:border-box; }} body {{ margin:0; background:radial-gradient(circle at top,#1b2944,#0c111d 58%); color:var(--ink); font:16px/1.5 system-ui,-apple-system,sans-serif; min-height:100vh; }}
main {{ max-width:760px; margin:0 auto; padding:64px 20px; }} .eyebrow {{ color:var(--accent); letter-spacing:.12em; text-transform:uppercase; font-size:.78rem; font-weight:700; }}
h1 {{ font-size:clamp(2rem,5vw,3.4rem); line-height:1.05; margin:.4rem 0 1rem; }} h2 {{ margin-top:0; }} p, li {{ color:var(--muted); }}
.card {{ background:rgba(21,29,45,.92); border:1px solid #2a3852; border-radius:18px; padding:24px; margin:20px 0; box-shadow:0 16px 50px rgba(0,0,0,.18); }}
label {{ display:block; color:var(--ink); font-weight:650; margin:14px 0 6px; }} input {{ width:100%; border:1px solid #3b4c6b; border-radius:10px; padding:12px 13px; background:#0e1625; color:var(--ink); font:inherit; }}
button {{ margin-top:16px; border:0; border-radius:10px; padding:12px 16px; background:var(--accent); color:#082118; font:inherit; font-weight:750; cursor:pointer; }} button.secondary {{ background:#273650; color:var(--ink); }}
.notice {{ border:1px solid #6d4d4d; border-radius:10px; padding:12px 14px; color:var(--danger); margin:14px 0; }} .ok {{ color:var(--accent); }} code {{ background:#0b1321; border:1px solid #2a3852; border-radius:6px; padding:2px 5px; color:#d9e6ff; }}
a {{ color:var(--accent); }} .small {{ font-size:.9rem; }} .grid {{ display:grid; gap:16px; grid-template-columns:repeat(auto-fit,minmax(260px,1fr)); }}
</style></head><body><main>{notice}{body}</main></body></html>"""
    )


def _auth_status() -> str:
    session = secure_session.load_session()
    if not session:
        return '<span style="color:var(--danger)">Not connected</span>'
    mode = html.escape(str(session.get("auth_mode", "unknown")))
    return f'<span class="ok">Connected ({mode} session)</span>'


async def health(_: Request) -> JSONResponse:
    return JSONResponse({"ok": True, "service": "monarch-mcp-server"})


async def oauth_protected_resource(request: Request) -> JSONResponse:
    base_url = _external_base_url(request)
    return JSONResponse(
        {
            "resource": f"{base_url}/mcp",
            "authorization_servers": [base_url],
            "scopes_supported": ["monarch"],
            "bearer_methods_supported": ["header"],
        }
    )


async def oauth_server_metadata(request: Request) -> JSONResponse:
    base_url = _external_base_url(request)
    return JSONResponse(
        {
            "issuer": base_url,
            "authorization_endpoint": f"{base_url}/oauth/authorize",
            "token_endpoint": f"{base_url}/oauth/token",
            "registration_endpoint": f"{base_url}/oauth/register",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code"],
            "code_challenge_methods_supported": ["S256"],
            "scopes_supported": ["monarch"],
            "token_endpoint_auth_methods_supported": ["none"],
        }
    )


async def _request_data(request: Request) -> dict[str, Any]:
    if "application/json" in request.headers.get("content-type", ""):
        data = await request.json()
        return data if isinstance(data, dict) else {}
    form = await request.form()
    return dict(form)


async def oauth_register(request: Request) -> JSONResponse:
    data = await _request_data(request)
    redirect_uris = data.get("redirect_uris", [])
    if isinstance(redirect_uris, str):
        redirect_uris = [redirect_uris]
    if not isinstance(redirect_uris, list) or not redirect_uris:
        return JSONResponse(
            {"error": "invalid_client_metadata", "error_description": "redirect_uris is required"},
            status_code=400,
        )
    client_id = f"mcp_{secrets.token_urlsafe(18)}"
    _oauth_clients[client_id] = {str(uri) for uri in redirect_uris}
    return JSONResponse(
        {
            "client_id": client_id,
            "client_id_issued_at": int(time.time()),
            "redirect_uris": list(_oauth_clients[client_id]),
            "token_endpoint_auth_method": "none",
        },
        status_code=201,
    )


def _oauth_authorize_page(params: dict[str, str], message: str = "") -> HTMLResponse:
    hidden = "".join(
        f'<input type="hidden" name="{html.escape(key)}" value="{html.escape(value)}">'
        for key, value in params.items()
        if key != "access_code"
    )
    return _page(
        "Authorize Monarch MCP",
        f"""<div class="eyebrow">Monarch MCP authorization</div><h1>Authorize access.</h1>
<p>Your MCP client is requesting access to this private Monarch deployment. Enter the Railway access code to approve the connection.</p>
<div class="card"><form method="post" action="/oauth/authorize">{hidden}<label for="access_code">Railway access code</label><input id="access_code" name="access_code" type="password" autocomplete="current-password" required autofocus><button type="submit">Approve MCP access</button></form></div>
<p class="small">This authorizes the MCP connection; Monarch login is completed separately from the <a href="/">setup dashboard</a>.</p>""",
        message=message,
    )


def _oauth_redirect_error(redirect_uri: str, error: str, state: str | None) -> RedirectResponse:
    params = {"error": error}
    if state:
        params["state"] = state
    return RedirectResponse(f"{redirect_uri}?{urlencode(params)}", status_code=303)


async def oauth_authorize(request: Request) -> Response:
    data = dict(request.query_params) if request.method == "GET" else await _request_data(request)
    client_id = str(data.get("client_id", ""))
    redirect_uri = str(data.get("redirect_uri", ""))
    state = str(data.get("state", "")) or None
    if client_id not in _oauth_clients or redirect_uri not in _oauth_clients[client_id]:
        return _page("Authorize Monarch MCP", "<h1>Invalid OAuth client.</h1>", message="The client or redirect URI was not registered.")
    if str(data.get("response_type", "")) != "code":
        return _oauth_redirect_error(redirect_uri, "unsupported_response_type", state)
    code_challenge = str(data.get("code_challenge", ""))
    if str(data.get("code_challenge_method", "")) != "S256" or not code_challenge:
        return _oauth_redirect_error(redirect_uri, "invalid_request", state)
    if request.method == "GET":
        if _has_access(request):
            data["access_code"] = _access_code()
        else:
            return _oauth_authorize_page({key: str(value) for key, value in data.items()})
    elif not _access_code() or not hmac.compare_digest(
        str(data.get("access_code", "")), _access_code()
    ):
        return _oauth_authorize_page(
            {key: str(value) for key, value in data.items()},
            "That access code was not accepted.",
        )

    authorization_code = secrets.token_urlsafe(32)
    _oauth_codes[authorization_code] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": code_challenge,
        "scope": str(data.get("scope", "monarch")),
        "expires_at": time.time() + _OAUTH_CODE_TTL_SECONDS,
    }
    params = {"code": authorization_code}
    if state:
        params["state"] = state
    return RedirectResponse(f"{redirect_uri}?{urlencode(params)}", status_code=303)


async def oauth_token(request: Request) -> JSONResponse:
    data = await _request_data(request)
    if str(data.get("grant_type", "")) != "authorization_code":
        return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)
    code = str(data.get("code", ""))
    record = _oauth_codes.pop(code, None)
    if not record or record["expires_at"] <= time.time():
        return JSONResponse({"error": "invalid_grant"}, status_code=400)
    if record["client_id"] != str(data.get("client_id", "")) or record["redirect_uri"] != str(data.get("redirect_uri", "")):
        return JSONResponse({"error": "invalid_grant"}, status_code=400)
    verifier = str(data.get("code_verifier", ""))
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    if not verifier or not hmac.compare_digest(challenge, record["code_challenge"]):
        return JSONResponse({"error": "invalid_grant"}, status_code=400)
    access_token = f"mcp_{secrets.token_urlsafe(32)}"
    _oauth_tokens[access_token] = time.time() + _OAUTH_TOKEN_TTL_SECONDS
    return JSONResponse(
        {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": _OAUTH_TOKEN_TTL_SECONDS,
            "scope": record["scope"],
        }
    )


async def home(request: Request) -> HTMLResponse:
    if not _has_access(request):
        if not _access_code():
            return _page(
                "Monarch MCP setup",
                f"""<div class="eyebrow">Monarch MCP</div><h1>One variable left.</h1>
<div class="card"><p>Set <code>{_ACCESS_ENV}</code> in Railway, redeploy, then reload this page.</p></div>""",
            )
        return _page(
            "Unlock Monarch MCP",
            f"""<div class="eyebrow">Monarch MCP</div><h1>Your private finance bridge.</h1>
<div class="card"><p>Enter the Railway access code to open the setup page. This code is never sent to Monarch.</p>
<form method="post" action="/unlock"><label for="access_code">Access code</label><input id="access_code" name="access_code" type="password" autocomplete="current-password" required autofocus><button type="submit">Unlock setup</button></form></div>
<p class="small">This deployment is designed for one Monarch account per Railway service.</p>""",
        )

    return _page(
        "Monarch MCP dashboard",
        f"""<div class="eyebrow">Monarch MCP</div><h1>Setup dashboard</h1>
<p>Connect one Monarch account to this Railway service, then point your MCP client at <code>/mcp</code>.</p>
<div class="card"><h2>Monarch status</h2><p>{_auth_status()}</p><a href="/auth">Open authentication</a></div>
<div class="card"><h2>MCP connection</h2><p>Endpoint: <code>{html.escape(_external_base_url(request))}/mcp</code></p><p class="small">For a client that supports custom bearer headers, send <code>Authorization: Bearer &lt;your access code&gt;</code>. Do not configure this server as unauthenticated once it has a Monarch session.</p></div>
<div class="card"><h2>Available tools</h2><p>{len(tool_catalog(mcp))} finance tools are registered and advertised through MCP.</p><p><a href="/tools">View the complete tool catalog</a></p></div>
<div class="card"><h2>Session storage</h2><p class="small">Railway's local filesystem is ephemeral. Set <code>MONARCH_MCP_SESSION_DIR=/data/monarch</code> and mount a Railway volume at <code>/data</code> if you want the login to survive redeploys.</p></div>
<form method="post" action="/logout"><button class="secondary" type="submit">Log out of Monarch</button></form>""",
    )


async def tools_page(request: Request) -> HTMLResponse | RedirectResponse:
    """Show the exact tool metadata advertised by the MCP endpoint."""
    if not _has_access(request):
        return RedirectResponse("/", status_code=303)
    rows = []
    for item in tool_catalog(mcp):
        flags = []
        if item["read_only"]:
            flags.append("read-only")
        if item["destructive"]:
            flags.append("destructive")
        flag_text = f" <span class=\"small\">({', '.join(flags)})</span>" if flags else ""
        rows.append(
            f"<li><strong>{html.escape(item['title'])}</strong> "
            f"<code>{html.escape(item['name'])}</code>{flag_text}"
            f"<br><span class=\"small\">{html.escape(item['description'])}</span></li>"
        )
    return _page(
        "Monarch MCP tools",
        f"""<div class="eyebrow">Monarch MCP</div><h1>Tool catalog</h1>
<p>This is the same 49-tool catalog returned by <code>tools/list</code>. The title, description, input schema, output schema, and safety annotations are advertised to MCP clients.</p>
<div class="card"><ol>{''.join(rows)}</ol></div>
<p><a href="/">Back to dashboard</a></p>""",
    )


async def unlock(request: Request) -> RedirectResponse | HTMLResponse:
    form = await request.form()
    submitted = str(form.get("access_code", ""))
    if not _access_code() or not hmac.compare_digest(submitted, _access_code()):
        return _page(
            "Unlock Monarch MCP",
            "<div class=\"eyebrow\">Monarch MCP</div><h1>Access denied.</h1><div class=\"card\"><p>That access code was not accepted.</p><a href=\"/\">Try again</a></div>",
        )
    response = RedirectResponse("/", status_code=303)
    response.set_cookie(
        _COOKIE_NAME,
        _make_session_cookie(),
        max_age=_COOKIE_TTL_SECONDS,
        httponly=True,
        secure=os.getenv("MONARCH_MCP_COOKIE_SECURE", "true").lower() != "false",
        samesite="lax",
    )
    return response


async def auth_page(request: Request, message: str = "") -> HTMLResponse:
    if not _has_access(request):
        return RedirectResponse("/", status_code=303)
    return _page(
        "Authenticate Monarch",
        f"""<div class="eyebrow">Monarch authentication</div><h1>Connect your account.</h1>
<p>These forms submit directly to this Railway service over HTTPS. Credentials are not exposed to the MCP model. Never reuse your Monarch password elsewhere.</p>
<div class="grid"><div class="card"><h2>Email and password</h2><p class="small">Monarch may ask for an email verification code or MFA code. If Cloudflare blocks this path, use browser cookies below.</p><form method="post" action="/auth/password"><label for="email">Email</label><input id="email" name="email" type="email" autocomplete="username" required><label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" required><label for="email_otp">Email code (if requested)</label><input id="email_otp" name="email_otp" inputmode="numeric" autocomplete="one-time-code"><label for="mfa_code">MFA code (if requested)</label><input id="mfa_code" name="mfa_code" inputmode="numeric" autocomplete="one-time-code"><button type="submit">Sign in</button></form></div>
<div class="card"><h2>Browser cookies</h2><p class="small">Recommended for SSO or Cloudflare-blocked accounts. In Monarch, copy the full <code>Cookie</code> request header from a request to <code>api.monarch.com</code>.</p><form method="post" action="/auth/cookies"><label for="cookie_string">Cookie header</label><input id="cookie_string" name="cookie_string" type="password" autocomplete="off" required><button type="submit">Verify and save cookies</button></form></div></div>
<div class="card"><h2>Legacy token</h2><p class="small">Only use this if you already have a working Monarch session token.</p><form method="post" action="/auth/token"><label for="token">Session token</label><input id="token" name="token" type="password" autocomplete="off" required><button type="submit">Verify and save token</button></form></div>
<p><a href="/">Back to dashboard</a></p>""",
        message=message,
    )


def _auth_error(message: str) -> HTMLResponse:
    return HTMLResponse(
        _page("Authenticate Monarch", "", message=message).body.decode("utf-8")
    )


async def auth_password(request: Request) -> HTMLResponse | RedirectResponse:
    if not _has_access(request):
        return RedirectResponse("/", status_code=303)
    form = await request.form()
    email = str(form.get("email", "")).strip()
    password = str(form.get("password", ""))
    email_otp = str(form.get("email_otp", "")).strip() or None
    mfa_code = str(form.get("mfa_code", "")).strip() or None
    if not email or not password:
        return await auth_page(request, "Email and password are required.")
    try:
        mm = await login_with_current_auth(
            email, password, email_otp=email_otp, mfa_code=mfa_code
        )
        secure_session.save_authenticated_session(mm)
    except EmailOtpRequiredException:
        return await auth_page(
            request,
            "Monarch sent an email verification code. Re-enter your email and password with that code, then submit again.",
        )
    except RequireMFAException:
        return await auth_page(
            request,
            "Monarch requires an MFA code. Re-enter your email and password with the current code, then submit again.",
        )
    except CaptchaRequiredException:
        return await auth_page(
            request,
            "Monarch blocked programmatic login with CAPTCHA. Use the browser-cookie option instead.",
        )
    except Exception:
        logger.exception("Monarch password login failed")
        return await auth_page(request, "Monarch login failed. Check the values and try again.")
    return RedirectResponse("/", status_code=303)


async def auth_cookies(request: Request) -> HTMLResponse | RedirectResponse:
    if not _has_access(request):
        return RedirectResponse("/", status_code=303)
    form = await request.form()
    cookie_string = str(form.get("cookie_string", "")).strip()
    if not cookie_string:
        return await auth_page(request, "A cookie header is required.")
    try:
        mm = await login_with_browser_cookies(cookie_string)
        secure_session.save_authenticated_session(mm)
    except Exception:
        logger.exception("Monarch cookie login failed")
        return await auth_page(request, "Cookie verification failed. Copy the full current Cookie header and try again.")
    return RedirectResponse("/", status_code=303)


async def auth_token(request: Request) -> HTMLResponse | RedirectResponse:
    if not _has_access(request):
        return RedirectResponse("/", status_code=303)
    form = await request.form()
    token = str(form.get("token", "")).strip()
    if not token:
        return await auth_page(request, "A session token is required.")
    try:
        from monarch_mcp_server.monarch_auth import create_monarch_client

        mm = create_monarch_client(token=token)
        await mm.get_subscription_details()
        secure_session.save_authenticated_session(mm)
    except Exception:
        logger.exception("Monarch token login failed")
        return await auth_page(request, "Token verification failed. Check the token and try again.")
    return RedirectResponse("/", status_code=303)


async def logout(request: Request) -> RedirectResponse:
    if _has_access(request):
        secure_session.delete_token()
    return RedirectResponse("/", status_code=303)


_mcp_app = mcp.streamable_http_app()
_mcp_app.routes.insert(0, Route("/health", health, methods=["GET"]))
_mcp_app.routes.insert(1, Route("/.well-known/oauth-protected-resource", oauth_protected_resource, methods=["GET"]))
_mcp_app.routes.insert(2, Route("/.well-known/oauth-authorization-server", oauth_server_metadata, methods=["GET"]))
_mcp_app.routes.insert(3, Route("/oauth/register", oauth_register, methods=["POST"]))
_mcp_app.routes.insert(4, Route("/oauth/authorize", oauth_authorize, methods=["GET", "POST"]))
_mcp_app.routes.insert(5, Route("/oauth/token", oauth_token, methods=["POST"]))
_mcp_app.routes.insert(6, Route("/", home, methods=["GET"]))
_mcp_app.routes.insert(7, Route("/tools", tools_page, methods=["GET"]))
_mcp_app.routes.insert(8, Route("/unlock", unlock, methods=["POST"]))
_mcp_app.routes.insert(9, Route("/auth", auth_page, methods=["GET"]))
_mcp_app.routes.insert(10, Route("/auth/password", auth_password, methods=["POST"]))
_mcp_app.routes.insert(11, Route("/auth/cookies", auth_cookies, methods=["POST"]))
_mcp_app.routes.insert(12, Route("/auth/token", auth_token, methods=["POST"]))
_mcp_app.routes.insert(13, Route("/logout", logout, methods=["POST"]))
_mcp_app.add_middleware(MCPAccessMiddleware)
app = _mcp_app


def main() -> None:
    """Run the Railway-friendly HTTP wrapper."""
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")


if __name__ == "__main__":
    main()
