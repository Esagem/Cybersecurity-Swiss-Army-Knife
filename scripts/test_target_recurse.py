"""Multi-port HTTP target designed to exercise slice 3's recursive collect.

Where this fits in the test-target line-up:

  * ``scripts/test_target.py`` — tiny single-port fixture, slice 2 smoke test.
  * ``scripts/test_target_heavy.py`` — multi-port + ground-truth manifest,
    used by the integration harness to score coverage against expected
    findings.
  * ``scripts/test_target_recurse.py`` — *this* file. Three ports; every
    "tier 0" endpoint links to "tier 1" endpoints, which link to "tier 2".
    The point is to give nuclei (or any recursion-aware tool) enough
    extractable URLs to exercise depth ≥ 2 of the recursion frontier.

The tier scheme:

    Tier 0 (root-discoverable; httpx finds these):
        http://127.0.0.1:8080/          ← landing page
        http://127.0.0.1:8081/          ← admin landing
        http://127.0.0.1:8443/          ← api landing

    Tier 1 (linked from /robots.txt + /sitemap.xml on each port):
        /admin, /api, /backup, /private, /.git/config, /.env

    Tier 2 (linked from tier-1 fixture content):
        /admin/db.sql, /api/v2/.env, /backup/index.php.bak,
        /private/.env.production, /admin/.git/HEAD

Each tier 1/2 endpoint serves content that *should* trigger at least
one nuclei template — so depth-1+ recursion produces new findings, not
just re-scans of the root URL.

Recursion behavior to look for in the live output of
``csak collect --recurse --max-depth=3 --target 127.0.0.1``::

    [csak] Depth 0 complete. Frontier: 12 typed targets extracted, ...
    [csak] Depth 1 (...): nuclei runs against /admin, /api, /backup ...
    [csak] Depth 2 (...): nuclei runs against /admin/db.sql ...

If httpx and nuclei behave as expected, you'll see findings appear at
depths > 0 in ``csak scan list --org demo`` (depth column on slice 3
schema).

Bound to 127.0.0.1 only — do not expose on a network.
"""
from __future__ import annotations

import argparse
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse


# ─────────────────────────────────────────────────────────────────────
# Tier 0 — landing pages with linked discovery endpoints
# ─────────────────────────────────────────────────────────────────────
#
# Roles, not literal ports. Each ``--ports`` entry is assigned a role
# in order: first → app, second → admin, third → api. The fixtures
# served by a port depend on its role, NOT its number, so the demo
# also works on alternate ports (18080, etc.) without redefinition.

ROLES = ("app", "admin", "api")


_LANDING = {
    "app": (
        b"<html><head><title>csak slice-3 test target - app</title>"
        b"</head><body>"
        b"<h1>App service</h1>"
        b"<p>Discovery files: <a href='/robots.txt'>robots.txt</a>, "
        b"<a href='/sitemap.xml'>sitemap.xml</a>, "
        b"<a href='/.well-known/security.txt'>security.txt</a></p>"
        b"</body></html>"
    ),
    "admin": (
        b"<html><head><title>Admin Panel</title></head><body>"
        b"<h1>Admin panel</h1>"
        b"<p>See <a href='/manager/html'>manager</a>, "
        b"<a href='/server-status'>status</a>.</p>"
        b"</body></html>"
    ),
    "api": (
        b"<html><head><title>API Gateway</title></head><body>"
        b"<h1>API gateway</h1>"
        b"<p>OpenAPI spec at <a href='/api/v1/swagger.json'>/api/v1/swagger.json</a>; "
        b"GraphQL at <a href='/graphql'>/graphql</a>.</p>"
        b"</body></html>"
    ),
}


def _robots_for(role: str) -> bytes:
    """robots.txt that intentionally lists tier-1 paths so the
    nuclei robots-txt template's URL extractor surfaces them.
    """
    paths = [
        "/admin",
        "/api/v1",
        "/api/v2",
        "/backup",
        "/private",
        "/.git/config",
        "/.env",
        "/server-status",
    ]
    body = "User-agent: *\n"
    for p in paths:
        body += f"Disallow: {p}\n"
    return body.encode("utf-8")


def _sitemap_for(role: str, port: int) -> bytes:
    """A real-shaped sitemap.xml — nuclei's exposed-sitemap-related
    templates can extract <loc> URLs into ``extracted-results``,
    seeding the depth-1 recursion frontier with concrete paths.
    """
    base = f"http://127.0.0.1:{port}"
    locs = [
        "/",
        "/admin",
        "/admin/login",
        "/admin/.git/config",
        "/admin/db.sql",
        "/api/v1/users",
        "/api/v2/.env",
        "/backup/index.php.bak",
        "/backup/db.sql",
        "/private/.env.production",
        "/private/notes.txt",
    ]
    body = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
    )
    for path in locs:
        body += f"  <url><loc>{base}{path}</loc></url>\n"
    body += "</urlset>\n"
    return body.encode("utf-8")


_SECURITY_TXT = (
    b"Contact: mailto:security@example.invalid\n"
    b"Encryption: http://127.0.0.1:8080/security/pgp.txt\n"
    b"Acknowledgments: http://127.0.0.1:8080/security/thanks\n"
)


# ─────────────────────────────────────────────────────────────────────
# Tier 1 / 2 — fixture endpoints that trigger nuclei templates
# ─────────────────────────────────────────────────────────────────────
#
# The bytes here are crafted to look like real disclosure content so
# nuclei's pattern-based detectors fire. None of it is sensitive — it's
# fixture data for testing csak's pipeline. Format mirrors the heavy
# target's fixtures.

FIXTURES: dict[str, tuple[int, bytes, str]] = {
    # ── Tier 1 ──────────────────────────────────────────────────────
    "/admin": (
        200,
        b"<html><body><h1>Admin panel</h1>"
        b"<p>See <a href='/admin/login'>login</a>, "
        b"<a href='/admin/.git/config'>.git</a>, "
        b"<a href='/admin/db.sql'>db.sql</a>.</p>"
        b"</body></html>",
        "text/html",
    ),
    "/admin/login": (
        200,
        b"<html><body><form method='post'><input name='u'>"
        b"<input name='p' type='password'></form></body></html>",
        "text/html",
    ),
    "/api/v1/users": (
        200,
        b'[{"id":1,"name":"alice"},{"id":2,"name":"bob"}]',
        "application/json",
    ),
    "/api/v1/swagger.json": (
        200,
        b'{"openapi":"3.0.0","info":{"title":"Demo API","version":"1.0.0"},'
        b'"paths":{"/users":{"get":{"summary":"List users"}},'
        b'"/admin/keys":{"get":{"summary":"Internal - list keys"}}}}',
        "application/json",
    ),
    "/api/v2": (
        200,
        b"<html><body><h2>API v2</h2></body></html>",
        "text/html",
    ),
    "/backup": (
        200,
        b"<html><body><h2>Backups</h2>"
        b"<a href='/backup/db.sql'>db.sql</a> "
        b"<a href='/backup/index.php.bak'>index.php.bak</a>"
        b"</body></html>",
        "text/html",
    ),
    "/private": (
        200,
        b"<html><body><h2>Private</h2></body></html>",
        "text/html",
    ),
    "/.env": (
        200,
        b"APP_ENV=production\n"
        b"APP_DEBUG=false\n"
        b"DB_PASSWORD=fake_test_password_not_real\n"
        b"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n",
        "text/plain",
    ),
    "/.git/config": (
        200,
        b"[core]\n\trepositoryformatversion = 0\n"
        b"[remote \"origin\"]\n"
        b"\turl = https://github.com/example/fake-test-repo.git\n",
        "text/plain",
    ),

    # ── Tier 2 (only reachable when crawled from tier 1 / sitemap) ──
    "/admin/.git/config": (
        200,
        b"[core]\n\trepositoryformatversion = 0\n"
        b"[remote \"origin\"]\n"
        b"\turl = https://github.com/example/admin-fake.git\n",
        "text/plain",
    ),
    "/admin/.git/HEAD": (
        200,
        b"ref: refs/heads/main\n",
        "text/plain",
    ),
    "/admin/db.sql": (
        200,
        b"-- MySQL dump 10.13\n"
        b"CREATE TABLE users (id INT, name VARCHAR(64), password VARCHAR(255));\n"
        b"INSERT INTO users VALUES (1, 'alice', 'fake_test_hash_not_real');\n",
        "application/sql",
    ),
    "/api/v2/.env": (
        200,
        b"API_KEY=fake_test_api_key_not_real\n"
        b"STRIPE_SECRET=sk_live_fake_test_not_real_xxxxxxxxxxxxxxxx\n"
        b"GITHUB_TOKEN=ghp_fakeTestNotReal0123456789abcdefghij\n",
        "text/plain",
    ),
    "/backup/index.php.bak": (
        200,
        b"<?php\n$db_password = 'fake_test_password_not_real';\n",
        "text/plain",
    ),
    "/backup/db.sql": (
        200,
        b"-- PostgreSQL dump\nCREATE TABLE secrets (key TEXT, value TEXT);\n",
        "application/sql",
    ),
    "/private/.env.production": (
        200,
        b"DB_PASSWORD=fake_prod_test_not_real\n"
        b"REDIS_URL=redis://fake.invalid:6379\n",
        "text/plain",
    ),
    "/private/notes.txt": (
        200,
        b"TODO: rotate the legacy production password\n",
        "text/plain",
    ),
    "/security/contact": (
        200,
        b"<html><body>Email security@example.invalid</body></html>",
        "text/html",
    ),

    # ── Server-info-style fixtures (detection templates fire) ───────
    "/server-status": (
        200,
        b"<html><head><title>Apache Server Status for 127.0.0.1</title></head>"
        b"<body><dl><dt>Server Version: Apache/2.2.0 (Unix)</dt>"
        b"<dt>Server MPM: prefork</dt></dl></body></html>",
        "text/html",
    ),
    "/server-info": (
        200,
        b"<html><body><h1>Apache Server Information</h1>"
        b"<dt>Server Version: Apache/2.2.0 (Unix)</dt></body></html>",
        "text/html",
    ),
    "/manager/html": (
        200,
        b"<html><body><h1>Tomcat Web Application Manager</h1></body></html>",
        "text/html",
    ),
    "/graphql": (
        200,
        b'{"data":{"__schema":{"queryType":{"name":"Query"},'
        b'"types":[{"name":"Query"},{"name":"User"},{"name":"Secret"}]}}}',
        "application/json",
    ),
}


# Per-role fingerprinting hooks (Apache server header, weak cookie,
# missing security headers — so technology / misconfiguration
# templates fire on the multi-port surface).

_ROLE_PROFILE: dict[str, dict[str, str]] = {
    "app": {
        "Server": "Apache/2.2.0 (Unix)",
        "X-Powered-By": "PHP/5.6.0",
        # NOTE: deliberately no Strict-Transport-Security, X-Frame-Options
        # — drives the "missing security headers" template.
    },
    "admin": {
        "Server": "nginx/1.13.0",
    },
    "api": {
        "Server": "Werkzeug/2.0.0 Python/3.10.0",
    },
}


# ─────────────────────────────────────────────────────────────────────
# Handlers
# ─────────────────────────────────────────────────────────────────────


def _make_handler(role: str, port: int) -> type[BaseHTTPRequestHandler]:
    profile = _ROLE_PROFILE.get(role, {})
    landing = _LANDING.get(role, b"<html><body>csak test target</body></html>")
    robots = _robots_for(role)
    sitemap = _sitemap_for(role, port)

    class Handler(BaseHTTPRequestHandler):
        # ``server_version`` flows into the ``Server:`` header that
        # nuclei's tech-detect templates fingerprint.
        server_version = profile.get("Server", "csak-test/0.1")
        sys_version = ""

        def do_GET(self) -> None:  # noqa: N802 — stdlib API
            path = urlparse(self.path).path
            if path == "/":
                return self._respond(200, landing, "text/html")
            if path == "/robots.txt":
                return self._respond(200, robots, "text/plain")
            if path == "/sitemap.xml":
                return self._respond(200, sitemap, "application/xml")
            if path == "/.well-known/security.txt":
                return self._respond(200, _SECURITY_TXT, "text/plain")
            if path in FIXTURES:
                status, body, ctype = FIXTURES[path]
                return self._respond(status, body, ctype)
            return self._respond(404, b"not found\n", "text/plain")

        def _respond(self, status: int, body: bytes, ctype: str) -> None:
            try:
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                # Weak cookie — exercises cookie-security templates.
                self.send_header("Set-Cookie", "session=fake_test_not_real")
                for k, v in profile.items():
                    if k.lower() == "server":
                        continue  # set via server_version
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(body)
            except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
                # Scanners slam connections shut. Don't crash the thread.
                pass

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            return  # quiet by default; --verbose toggles below

        def handle_one_request(self) -> None:
            try:
                super().handle_one_request()
            except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
                self.close_connection = True

    return Handler


def _run_servers(ports: list[int], verbose: bool) -> list[tuple[str, ThreadingHTTPServer]]:
    servers: list[tuple[str, ThreadingHTTPServer]] = []
    # First port -> "app", second -> "admin", third -> "api"; later
    # ports recycle through the roles for the rare case of >3 ports.
    for i, port in enumerate(ports):
        role = ROLES[i % len(ROLES)]
        handler = _make_handler(role, port)
        if verbose:
            handler.log_message = (  # type: ignore[method-assign]
                lambda self, format, *a: print(
                    f"[{self.server.server_port}] {self.address_string()} "
                    f"{format % a}"
                )
            )
        srv = ThreadingHTTPServer(("127.0.0.1", port), handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append((role, srv))
    return servers


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--ports",
        type=str,
        default="8080,8081,8443",
        help="Comma-separated ports to bind on 127.0.0.1.",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Print access logs."
    )
    args = parser.parse_args()
    ports = [int(p.strip()) for p in args.ports.split(",") if p.strip()]

    servers = _run_servers(ports, args.verbose)
    print("csak slice-3 recursive test target -- bound to 127.0.0.1 only")
    for role, s in servers:
        port = s.server_port
        print(f"  http://127.0.0.1:{port}/   role={role:<5} "
              f"(landing + /robots.txt + /sitemap.xml + tier-1/2 fixtures)")
    print()
    print("Try:")
    first_port = servers[0][1].server_port if servers else 8080
    print(f"  csak collect --org demo --target 127.0.0.1:{first_port} "
          "--recurse --max-depth 3")
    print("  csak scan list --org demo            # depth column shows recursion")
    print("Ctrl+C to stop.")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("\nstopping.")
        for _, s in servers:
            s.shutdown()


if __name__ == "__main__":
    main()
