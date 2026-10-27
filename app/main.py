"""MarketGuard: an intentionally vulnerable + hardened AppSec lab.

Run with:
  LAB_MODE=vulnerable python -m app.main
  LAB_MODE=secure python -m app.main

Only run the vulnerable mode on localhost or in an isolated lab environment.
"""

from __future__ import annotations

import json
import os
from http import cookies
from urllib.parse import parse_qs
from wsgiref.simple_server import make_server

from app.security import csrf_token, escape, sign_session, valid_csrf, verify_session
from app.state import REVIEWS, USERS, reset_state

MODE = os.environ.get("LAB_MODE", "secure").lower()
if MODE not in {"vulnerable", "secure"}:
    raise RuntimeError("LAB_MODE must be 'vulnerable' or 'secure'")


def _parse_cookies(environ):
    jar = cookies.SimpleCookie()
    jar.load(environ.get("HTTP_COOKIE", ""))
    return {k: morsel.value for k, morsel in jar.items()}


def _body(environ):
    length = int(environ.get("CONTENT_LENGTH") or 0)
    return environ["wsgi.input"].read(length).decode("utf-8", errors="replace") if length else ""


def _form(environ):
    return {k: v[-1] for k, v in parse_qs(_body(environ), keep_blank_values=True).items()}


def _json_body(environ):
    try:
        return json.loads(_body(environ) or "{}")
    except json.JSONDecodeError:
        return {}


def _response(start_response, body, status="200 OK", headers=None, content_type="text/html; charset=utf-8"):
    encoded = body.encode("utf-8") if isinstance(body, str) else body
    base_headers = [("Content-Type", content_type), ("Content-Length", str(len(encoded)))]
    start_response(status, base_headers + (headers or []))
    return [encoded]


def _json_response(start_response, payload, status="200 OK", headers=None):
    return _response(
        start_response,
        json.dumps(payload, separators=(",", ":")),
        status=status,
        headers=headers,
        content_type="application/json; charset=utf-8",
    )


def _query(environ):
    return {k: v[-1] for k, v in parse_qs(environ.get("QUERY_STRING", ""), keep_blank_values=True).items()}


def _current_user(environ):
    jar = _parse_cookies(environ)
    if MODE == "vulnerable":
        return jar.get("user")
    return verify_session(jar.get("session"))


def _role(environ):
    jar = _parse_cookies(environ)
    if MODE == "vulnerable":
        # Intentional flaw: authorization trusts a client-controlled cookie.
        return jar.get("role", "guest")
    username = verify_session(jar.get("session"))
    return USERS.get(username, {}).get("role", "guest") if username else "guest"


def _page(title, content):
    return f"""<!doctype html>
<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">
<title>{escape(title)}</title>
<style>
body{{font-family:system-ui,sans-serif;max-width:920px;margin:40px auto;padding:0 20px;line-height:1.5}}
nav a{{margin-right:14px}} code,pre{{background:#f3f3f3;padding:2px 5px;border-radius:4px}} .card{{border:1px solid #ddd;border-radius:10px;padding:16px;margin:14px 0}}
.badge{{font-size:.8rem;padding:3px 8px;border:1px solid #999;border-radius:999px}}
</style></head><body>
<nav><a href=\"/\">Home</a><a href=\"/search\">Search</a><a href=\"/reviews\">Reviews</a><a href=\"/account\">Account</a><a href=\"/admin\">Admin</a></nav>
<h1>{escape(title)}</h1><p><span class=\"badge\">mode: {MODE}</span></p>{content}</body></html>"""


def application(environ, start_response):
    path = environ.get("PATH_INFO", "/")
    method = environ.get("REQUEST_METHOD", "GET").upper()

    if path == "/health":
        return _json_response(start_response, {"status": "ok", "mode": MODE})

    if path == "/reset" and method == "POST":
        reset_state()
        return _json_response(start_response, {"reset": True})

    if path == "/":
        content = """
<p>MarketGuard is a deliberately small marketplace used to demonstrate exploit-to-remediation AppSec workflows.</p>
<div class=\"card\"><strong>Demo logins</strong><br>
<a href=\"/login?user=member\">member</a> · <a href=\"/login?user=admin\">admin</a></div>
<div class=\"card\"><strong>Modules</strong>: reflected XSS, stored XSS, CSRF, broken access control, CORS exposure, and business-logic validation.</div>
"""
        return _response(start_response, _page("MarketGuard AppSec Lab", content))

    if path == "/login":
        username = _query(environ).get("user", "member")
        if username not in USERS:
            return _response(start_response, _page("Login", "Unknown demo user"), "404 Not Found")
        if MODE == "vulnerable":
            headers = [
                ("Set-Cookie", f"user={username}; Path=/; SameSite=Lax"),
                ("Set-Cookie", f"role={USERS[username]['role']}; Path=/; SameSite=Lax"),
            ]
        else:
            token = sign_session(username)
            headers = [("Set-Cookie", f"session={token}; Path=/; HttpOnly; SameSite=Strict")]
        return _response(start_response, _page("Login", f"Logged in as <strong>{escape(username)}</strong>."), headers=headers)

    if path == "/search":
        q = _query(environ).get("q", "")
        rendered = q if MODE == "vulnerable" else escape(q)
        content = f"""
<form method=\"get\"><label>Search <input name=\"q\" value=\"{escape(q)}\"></label><button>Go</button></form>
<div class=\"card\">Results for: <strong>{rendered}</strong></div>
"""
        return _response(start_response, _page("Product Search", content))

    if path == "/reviews" and method == "POST":
        form = _form(environ)
        body = form.get("body", "")[:500]
        REVIEWS.append(body)
        return _response(start_response, "", "303 See Other", [("Location", "/reviews")])

    if path == "/reviews":
        blocks = []
        for review in REVIEWS:
            rendered = review if MODE == "vulnerable" else escape(review)
            blocks.append(f'<div class="card">{rendered}</div>')
        content = """
<form method=\"post\"><textarea name=\"body\" rows=\"4\" cols=\"60\" placeholder=\"Write a review\"></textarea><br><button>Post review</button></form>
""" + ("".join(blocks) or "<p>No reviews yet.</p>")
        return _response(start_response, _page("Product Reviews", content))

    if path == "/account":
        username = _current_user(environ)
        if not username or username not in USERS:
            return _response(start_response, _page("Account", "Login first."), "401 Unauthorized")
        jar = _parse_cookies(environ)
        token_html = ""
        if MODE == "secure":
            token_html = f'<input type="hidden" name="csrf" value="{csrf_token(jar["session"])}">'
        content = f"""
<p>User: <strong>{escape(username)}</strong></p><p>Email: {escape(USERS[username]['email'])}</p>
<form action=\"/account/email\" method=\"post\">{token_html}
<label>New email <input name=\"email\" value=\"{escape(USERS[username]['email'])}\"></label><button>Update</button></form>
"""
        return _response(start_response, _page("Account", content))

    if path == "/account/email" and method == "POST":
        username = _current_user(environ)
        if not username or username not in USERS:
            return _response(start_response, "Unauthorized", "401 Unauthorized")
        form = _form(environ)
        if MODE == "secure":
            session_token = _parse_cookies(environ).get("session")
            if not valid_csrf(session_token, form.get("csrf")):
                return _response(start_response, "CSRF validation failed", "403 Forbidden", content_type="text/plain")
        email = form.get("email", "")
        if MODE == "secure" and ("@" not in email or len(email) > 120):
            return _response(start_response, "Invalid email", "400 Bad Request", content_type="text/plain")
        USERS[username]["email"] = email[:200]
        return _response(start_response, "", "303 See Other", [("Location", "/account")])

    if path == "/admin":
        if _role(environ) != "admin":
            return _response(start_response, _page("Admin", "Forbidden"), "403 Forbidden")
        users = "".join(f"<li>{escape(u)} — {escape(v['role'])}</li>" for u, v in USERS.items())
        return _response(start_response, _page("Admin", f"<p>Administrative console.</p><ul>{users}</ul>"))

    if path == "/api/admin/users":
        origin = environ.get("HTTP_ORIGIN", "")
        data = [{"username": u, "email": v["email"], "role": v["role"]} for u, v in USERS.items()]
        headers = []
        if MODE == "vulnerable":
            # Intentional misconfiguration: sensitive data is readable cross-origin.
            headers.append(("Access-Control-Allow-Origin", "*"))
        elif origin == "http://localhost:5001":
            headers.extend([("Access-Control-Allow-Origin", origin), ("Vary", "Origin")])
        if MODE == "secure" and _role(environ) != "admin":
            return _json_response(start_response, {"error": "forbidden"}, "403 Forbidden", headers)
        return _json_response(start_response, {"users": data}, headers=headers)

    if path == "/api/rewards":
        return _json_response(
            start_response,
            {"accounts": [{"username": u, "points": v["points"]} for u, v in USERS.items()]},
        )

    if path == "/api/rewards/redeem" and method == "POST":
        if _role(environ) != "admin":
            return _json_response(start_response, {"error": "admin required"}, "403 Forbidden")
        data = _json_body(environ)
        username = str(data.get("username", ""))
        try:
            amount = int(data.get("amount"))
        except (TypeError, ValueError):
            return _json_response(start_response, {"error": "amount must be an integer"}, "400 Bad Request")
        if username not in USERS:
            return _json_response(start_response, {"error": "unknown user"}, "404 Not Found")
        if MODE == "secure":
            if amount <= 0:
                return _json_response(start_response, {"error": "amount must be positive"}, "400 Bad Request")
            if amount > USERS[username]["points"]:
                return _json_response(start_response, {"error": "insufficient points"}, "409 Conflict")
        # Vulnerable mode intentionally permits negative redemptions, increasing the balance.
        USERS[username]["points"] -= amount
        return _json_response(start_response, {"username": username, "remainingPoints": USERS[username]["points"]})

    return _response(start_response, _page("Not Found", "No route here."), "404 Not Found")


def main():
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5001" if MODE == "secure" else "5000"))
    print(f"MarketGuard running in {MODE} mode at http://{host}:{port}")
    with make_server(host, port, application) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
