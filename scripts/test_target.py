"""Local HTTP target for exercising ``csak collect`` end-to-end.

Serves a handful of predictable endpoints on ``127.0.0.1:8080`` so
you can verify the collect → ingest → findings pipeline without
touching real internet infrastructure.

Why port 8080: httpx (ProjectDiscovery) probes ``80, 8080, 443,
8443`` by default. Picking 8080 means a bare ``--target 127.0.0.1``
works out of the box — no port-override flag dance.

Usage::

    python scripts/test_target.py                # runs until Ctrl+C
    python scripts/test_target.py --port 9000    # custom port (won't be probed by httpx)

Then in another terminal::

    csak org create demo
    csak collect --org demo --target 127.0.0.1 --mode standard
    csak findings list --org demo

``standard`` mode runs httpx + nuclei. ``quick`` skips nuclei, so
findings will be sparse.

This is for local testing only — bound to 127.0.0.1, do not expose
on a network.
"""
from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer

# Endpoint → (body, content-type). Picked to look like the kinds of
# things web scanners notice: a robots.txt, an exposed .env, an
# obvious /admin path, a login form. None of this is sensitive — it's
# fixture data for testing the csak pipeline.
PAGES: dict[str, tuple[bytes, str]] = {
    "/": (
        b"<html><head><title>csak test target</title></head>"
        b"<body><h1>csak test target</h1>"
        b"<p>Endpoints: <a href='/admin'>/admin</a>, "
        b"<a href='/.env'>/.env</a>, <a href='/login'>/login</a>, "
        b"<a href='/robots.txt'>/robots.txt</a>"
        b"</p></body></html>",
        "text/html",
    ),
    "/admin": (
        b"<html><body><h2>Admin panel</h2><p>Login required.</p></body></html>",
        "text/html",
    ),
    "/login": (
        b"<html><body><form method='post' action='/login'>"
        b"username: <input name='u'><br>"
        b"password: <input name='p' type='password'><br>"
        b"<button>sign in</button></form></body></html>",
        "text/html",
    ),
    "/.env": (
        b"DB_PASSWORD=fake_test_password_not_real\n"
        b"API_KEY=fake_test_key_not_real\n",
        "text/plain",
    ),
    "/robots.txt": (
        b"User-agent: *\nDisallow: /admin\nDisallow: /.env\n",
        "text/plain",
    ),
}


class TargetHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 — stdlib API
        path = self.path.split("?", 1)[0]
        body, content_type = PAGES.get(path, (b"not found\n", "text/plain"))
        status = 200 if path in PAGES else 404
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Server", "csak-test-target/0.1")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        # Quiet by default — uncomment the next line to see access logs.
        # print(f"[{self.address_string()}] {format % args}")
        return


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Print access logs."
    )
    args = parser.parse_args()

    if args.verbose:
        TargetHandler.log_message = (  # type: ignore[method-assign]
            lambda self, format, *a: print(
                f"[{self.address_string()}] {format % a}"
            )
        )

    server = HTTPServer(("127.0.0.1", args.port), TargetHandler)
    print(f"csak test target listening on http://127.0.0.1:{args.port}")
    print("Endpoints: /  /admin  /login  /.env  /robots.txt")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopping.")


if __name__ == "__main__":
    main()
