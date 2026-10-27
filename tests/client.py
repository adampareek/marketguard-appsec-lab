from __future__ import annotations

from io import BytesIO
from urllib.parse import urlencode

import app.main as webapp


class Response:
    def __init__(self, status, headers, body):
        self.status = status
        self.status_code = int(status.split()[0])
        self.headers = headers
        self.body = body.decode("utf-8", errors="replace")

    def header_values(self, name):
        lname = name.lower()
        return [v for k, v in self.headers if k.lower() == lname]


class Client:
    def __init__(self, mode="secure"):
        self.mode = mode
        self.cookies = {}

    def _cookie_header(self):
        return "; ".join(f"{k}={v}" for k, v in self.cookies.items())

    def request(self, path, method="GET", data=None, json_body=None, headers=None):
        webapp.MODE = self.mode
        query = ""
        if "?" in path:
            path, query = path.split("?", 1)

        body = b""
        content_type = ""
        if data is not None:
            body = urlencode(data).encode()
            content_type = "application/x-www-form-urlencoded"
        if json_body is not None:
            import json
            body = json.dumps(json_body).encode()
            content_type = "application/json"

        environ = {
            "REQUEST_METHOD": method,
            "PATH_INFO": path,
            "QUERY_STRING": query,
            "CONTENT_LENGTH": str(len(body)),
            "CONTENT_TYPE": content_type,
            "wsgi.input": BytesIO(body),
            "SERVER_NAME": "localhost",
            "SERVER_PORT": "5000" if self.mode == "vulnerable" else "5001",
            "wsgi.url_scheme": "http",
        }
        if self.cookies:
            environ["HTTP_COOKIE"] = self._cookie_header()
        for key, value in (headers or {}).items():
            environ["HTTP_" + key.upper().replace("-", "_")] = value

        captured = {}

        def start_response(status, response_headers):
            captured["status"] = status
            captured["headers"] = response_headers

        response_body = b"".join(webapp.application(environ, start_response))
        response = Response(captured["status"], captured["headers"], response_body)
        for cookie in response.header_values("Set-Cookie"):
            pair = cookie.split(";", 1)[0]
            name, value = pair.split("=", 1)
            self.cookies[name] = value
        return response
