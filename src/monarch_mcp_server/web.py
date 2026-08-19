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

import uvicorn
from monarchmoney import CaptchaRequiredException, RequireMFAException
from starlette.applications import Starlette
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from starlette.routing import Route

from monarch_mcp_server.app import mcp
from monarch_mcp_server.monarch_auth import (
    EmailOtpRequiredException,
    login_with_browser_cookies,
    login_with_current_auth,
)
from monarch_mcp_server.secure_session import secure_session

logger = logging.getLogger(__name__)

_ACCESS_ENV = "MONARCH_MCP_ACCESS_CODE"
_COOKIE_NAME = "monarch_mcp_session"
_COOKIE_TTL_SECONDS = 24 * 60 * 60


def _access_code() -> str:
    return os.getenv(_ACCESS_ENV, "").strip()


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
    return scheme.lower() == "bearer" and hmac.compare_digest(
        token.strip(), _access_code()
    )


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
                "Authorization: Bearer <access code>.",
                status_code=401,
                headers={"WWW-Authenticate": 'Bearer realm="Monarch MCP"'},
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
<div class="card"><h2>MCP connection</h2><p>Endpoint: <code>{html.escape(str(request.base_url).rstrip('/'))}/mcp</code></p><p class="small">For a client that supports custom bearer headers, send <code>Authorization: Bearer &lt;your access code&gt;</code>. Do not configure this server as unauthenticated once it has a Monarch session.</p></div>
<div class="card"><h2>Session storage</h2><p class="small">Railway's local filesystem is ephemeral. Set <code>MONARCH_MCP_SESSION_DIR=/data/monarch</code> and mount a Railway volume at <code>/data</code> if you want the login to survive redeploys.</p></div>
<form method="post" action="/logout"><button class="secondary" type="submit">Log out of Monarch</button></form>""",
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
_mcp_app.routes.insert(1, Route("/", home, methods=["GET"]))
_mcp_app.routes.insert(2, Route("/unlock", unlock, methods=["POST"]))
_mcp_app.routes.insert(3, Route("/auth", auth_page, methods=["GET"]))
_mcp_app.routes.insert(4, Route("/auth/password", auth_password, methods=["POST"]))
_mcp_app.routes.insert(5, Route("/auth/cookies", auth_cookies, methods=["POST"]))
_mcp_app.routes.insert(6, Route("/auth/token", auth_token, methods=["POST"]))
_mcp_app.routes.insert(7, Route("/logout", logout, methods=["POST"]))
_mcp_app.add_middleware(MCPAccessMiddleware)
app = _mcp_app


def main() -> None:
    """Run the Railway-friendly HTTP wrapper."""
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")


if __name__ == "__main__":
    main()
