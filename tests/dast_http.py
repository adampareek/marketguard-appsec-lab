"""Black-box HTTP checks against a running hardened MarketGuard service."""

import json
import os
import re
import sys
from http.cookiejar import CookieJar
from urllib.error import HTTPError
from urllib.parse import quote, urlencode
from urllib.request import HTTPCookieProcessor, Request, build_opener, urlopen

BASE = os.environ.get("DAST_TARGET", "http://127.0.0.1:5001")
if not BASE.startswith(("http://127.0.0.1:", "http://localhost:")):
    raise SystemExit("DAST_TARGET must be localhost/127.0.0.1")


def status(req):
    try:
        return urlopen(req).status
    except HTTPError as exc:
        return exc.code


failures = []

payload = '<img src=x onerror=alert(1)>'
body = urlopen(BASE + "/search?q=" + quote(payload)).read().decode()
if payload in body:
    failures.append("Reflected XSS payload rendered unescaped")

req = Request(BASE + "/admin", headers={"Cookie": "role=admin"})
if status(req) != 403:
    failures.append("Client-controlled role cookie reached /admin")

req = Request(BASE + "/api/admin/users", headers={"Origin": "https://untrusted.example"})
try:
    resp = urlopen(req)
    code = resp.status
    acao = resp.headers.get("Access-Control-Allow-Origin")
except HTTPError as exc:
    code = exc.code
    acao = exc.headers.get("Access-Control-Allow-Origin")
if code != 403 or acao == "*":
    failures.append("Sensitive admin API is exposed cross-origin")

jar = CookieJar()
opener = build_opener(HTTPCookieProcessor(jar))
opener.open(BASE + "/login?user=admin").read()
negative = Request(
    BASE + "/api/rewards/redeem",
    data=json.dumps({"username": "member", "amount": -50}).encode(),
    method="POST",
    headers={"Content-Type": "application/json"},
)
try:
    response = opener.open(negative)
    code = response.status
except HTTPError as exc:
    code = exc.code
if code != 400:
    failures.append("Negative reward redemption was not rejected")

jar = CookieJar()
opener = build_opener(HTTPCookieProcessor(jar))
opener.open(BASE + "/login?user=member").read()
csrf_missing = Request(
    BASE + "/account/email",
    data=urlencode({"email": "attacker@example.test"}).encode(),
    method="POST",
    headers={"Content-Type": "application/x-www-form-urlencoded"},
)
try:
    response = opener.open(csrf_missing)
    code = response.status
except HTTPError as exc:
    code = exc.code
if code != 403:
    failures.append("State-changing account request accepted without CSRF token")

if failures:
    print("DAST FAILED")
    for item in failures:
        print(" -", item)
    sys.exit(1)

print("DAST PASSED: hardened service rejected tested exploit paths")
