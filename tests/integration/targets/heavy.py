"""Heavy multi-port HTTP target with a full ground-truth manifest.

Each intentionally-introduced exposure has an ``Expectation`` entry
declaring what csak *should* surface for it. The integration harness
runs csak against this target, collects findings, and diffs against
the manifest to produce a coverage report.

The server logic itself is intentionally simple and stdlib-only so
the harness can spawn it programmatically without external deps.
Bound to 127.0.0.1 — do not expose on a network.
"""
from __future__ import annotations

import base64
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable
from urllib.parse import parse_qs, urlparse

from tests.integration.manifest import Expectation, TargetSpec

# ---------------------------------------------------------------------------
# Fixture data
# ---------------------------------------------------------------------------

APP_FIXTURES: dict[str, tuple[int, bytes, str, dict[str, str]]] = {
    "/": (
        200,
        b"<html><head><title>csak heavy test target</title></head>"
        b"<body><h1>App</h1></body></html>",
        "text/html",
        {},
    ),
    "/.env": (
        200,
        # NOTE: the value patterns matter. We craft these to look like
        # real credential leaks so nuclei's pattern-based detectors
        # (aws-key-disclosure, jwt-disclosure, etc.) can fire.
        b"APP_KEY=base64:fake_test_app_key_not_real_for_use_xxxxxxxxxxxxxxxxxxxx\n"
        b"DB_HOST=db.example.com\n"
        b"DB_PASSWORD=fake_test_password_not_real\n"
        b"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        b"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        b"STRIPE_SECRET=sk_live_fake_test_not_real_xxxxxxxxxxxxxxxx\n"
        b"GITHUB_TOKEN=ghp_fakeTestNotReal0123456789abcdefghij\n",
        "text/plain",
        {},
    ),
    "/.git/config": (
        200,
        b"[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n"
        b"[remote \"origin\"]\n"
        b"\turl = https://github.com/example/fake-test-repo.git\n"
        b"\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
        b"[branch \"main\"]\n\tremote = origin\n\tmerge = refs/heads/main\n",
        "text/plain",
        {},
    ),
    "/.git/HEAD": (200, b"ref: refs/heads/main\n", "text/plain", {}),
    "/.DS_Store": (
        200,
        b"\x00\x00\x00\x01Bud1\x00\x00\x10\x00\x00\x00\x08\x00\x00\x10\x00",
        "application/octet-stream",
        {},
    ),
    "/web.config": (
        200,
        b"<?xml version=\"1.0\"?>\n<configuration>\n"
        b"  <connectionStrings>\n"
        b"    <add name=\"Default\" "
        b"connectionString=\"Server=fake;Database=fake;Password=fake_not_real\"/>\n"
        b"  </connectionStrings>\n</configuration>\n",
        "application/xml",
        {},
    ),
    "/.htaccess": (
        200,
        b"AuthType Basic\nAuthName \"Restricted\"\nRequire valid-user\n",
        "text/plain",
        {},
    ),
    "/index.php.bak": (
        200,
        b"<?php\n$db_password = 'fake_test_password_not_real';\n",
        "text/plain",
        {},
    ),
    "/config.php~": (
        200,
        b"<?php\n$DB_HOST='localhost';\n$DB_PASS='fake_not_real';\n",
        "text/plain",
        {},
    ),
    "/server-status": (
        200,
        b"<html><head><title>Apache Server Status for 127.0.0.1</title></head>\n"
        b"<body><h1>Apache Server Status for 127.0.0.1</h1>\n"
        b"<dl><dt>Server Version: Apache/2.2.0 (Unix)</dt>\n"
        b"<dt>Server MPM: prefork</dt>\n</dl></body></html>",
        "text/html",
        {},
    ),
    "/server-info": (
        200,
        b"<html><body><h1>Apache Server Information</h1>"
        b"<dt>Server Version: Apache/2.2.0 (Unix)</dt></body></html>",
        "text/html",
        {},
    ),
    "/phpinfo.php": (
        200,
        b"<html><head><title>phpinfo()</title></head>\n"
        b"<body><h1 class=\"p\">PHP Version 5.6.0</h1>\n"
        b"<h2>System</h2>\n<table><tr><td>System</td>"
        b"<td>Linux fakehost 4.15.0</td></tr></table></body></html>",
        "text/html",
        {},
    ),
    "/swagger.json": (
        200,
        b"{\"openapi\":\"3.0.0\",\"info\":{\"title\":\"Fake API\",\"version\":\"1.0.0\"},"
        b"\"paths\":{\"/users\":{\"get\":{\"summary\":\"list\"}}}}",
        "application/json",
        {},
    ),
    "/api-docs": (
        200,
        b"<html><body><h1>API Documentation</h1></body></html>",
        "text/html",
        {},
    ),
    "/graphql": (
        200,
        b"{\"data\":{\"__schema\":{\"queryType\":{\"name\":\"Query\"},"
        b"\"types\":[{\"name\":\"Query\"},{\"name\":\"User\"}]}}}",
        "application/json",
        {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        },
    ),
    "/api/v1/users": (
        200,
        b"[{\"id\":1,\"username\":\"alice\"}]",
        "application/json",
        {"Access-Control-Allow-Origin": "*"},
    ),
    "/robots.txt": (
        200,
        b"User-agent: *\nDisallow: /admin\nDisallow: /.env\nDisallow: /api\n"
        b"Disallow: /backup\nDisallow: /old\nDisallow: /.git\n",
        "text/plain",
        {},
    ),
}


class AppHandler(BaseHTTPRequestHandler):
    server_version = "Apache/2.2.0"
    sys_version = "PHP/5.6.0"

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        if parsed.path == "/redir":
            for key in ("next", "redirect", "url"):
                if key in params:
                    self.send_response(302)
                    self.send_header("Location", params[key][0])
                    self.end_headers()
                    return

        if parsed.path == "/search":
            q = params.get("q", [""])[0].encode("utf-8", "replace")
            body = b"<html><body>Results for: " + q + b"</body></html>"
            self._respond(200, body, "text/html")
            return

        if parsed.path in APP_FIXTURES:
            status, body, ctype, extra = APP_FIXTURES[parsed.path]
            self._respond(status, body, ctype, extra)
            return

        self._respond(404, b"not found\n", "text/plain")

    def _respond(self, status, body, ctype, extra=None):
        try:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            # Intentionally no security headers, weak cookie.
            self.send_header("Set-Cookie", "session=fake_test_session_not_real")
            if extra:
                for k, v in extra.items():
                    self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            # Scanners frequently slam connections shut mid-response.
            # Not worth a stack trace each time.
            pass

    def log_message(self, format, *args):
        return

    def handle_one_request(self):
        try:
            super().handle_one_request()
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            self.close_connection = True


ADMIN_CREDS_B64 = base64.b64encode(b"admin:admin").decode()

ADMIN_FIXTURES: dict[str, tuple[int, bytes, str]] = {
    "/": (
        200,
        b"<html><head><title>Admin Panel</title></head>"
        b"<body><h1>Admin Panel</h1></body></html>",
        "text/html",
    ),
    "/users": (
        200,
        b"[{\"id\":1,\"name\":\"alice\",\"role\":\"admin\"}]",
        "application/json",
    ),
    "/config": (
        200,
        b"{\"db_password\":\"fake_test_not_real\",\"jwt_secret\":\"fake_test\"}",
        "application/json",
    ),
    "/manager/html": (
        200,
        b"<html><body><h1>Tomcat Web Application Manager</h1></body></html>",
        "text/html",
    ),
    "/wp-login.php": (
        200,
        b"<html><head><title>Log In &lsaquo; WordPress</title></head>"
        b"<body><form id='loginform' action='wp-login.php'></form></body></html>",
        "text/html",
    ),
}


class AdminHandler(BaseHTTPRequestHandler):
    server_version = "nginx/1.13.0"
    sys_version = ""

    def do_GET(self) -> None:  # noqa: N802
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Basic ") or auth.split(" ", 1)[1].strip() != ADMIN_CREDS_B64:
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="Admin"')
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        path = urlparse(self.path).path
        if path in ADMIN_FIXTURES:
            status, body, ctype = ADMIN_FIXTURES[path]
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, format, *args):
        return


# ---------------------------------------------------------------------------
# Launcher used by the harness
# ---------------------------------------------------------------------------


def launch(app_port: int = 8080, admin_port: int = 8000) -> tuple[Callable[[], None], str]:
    """Spin up both services in background threads. Returns
    ``(stop, target_arg)`` — call ``stop()`` to shut down, pass
    ``target_arg`` to ``csak collect --target``."""
    app = ThreadingHTTPServer(("127.0.0.1", app_port), AppHandler)
    admin = ThreadingHTTPServer(("127.0.0.1", admin_port), AdminHandler)
    threading.Thread(target=app.serve_forever, daemon=True).start()
    threading.Thread(target=admin.serve_forever, daemon=True).start()

    def stop() -> None:
        app.shutdown()
        admin.shutdown()

    return stop, "127.0.0.1"


# ---------------------------------------------------------------------------
# Ground truth — what csak SHOULD find. Each entry is independently
# verifiable. Mark ``known_gap=True`` for cases we know are currently
# missed and want to track without failing CI.
# ---------------------------------------------------------------------------

_EXPECTATIONS: tuple[Expectation, ...] = (
    # ── Multi-port surface (httpx) ──────────────────────────────────────
    Expectation(
        description="App service detected on port 8080",
        vuln_class="surface-discovery",
        expected_severity="info",
        target_path_contains=("127.0.0.1:8080",),
    ),
    Expectation(
        description="Admin service detected on port 8000 (HTTP 401)",
        vuln_class="surface-discovery",
        expected_severity="info",
        target_path_contains=("127.0.0.1:8000",),
    ),

    # ── VCS metadata leaks (nuclei) ─────────────────────────────────────
    Expectation(
        description="/.git/config exposed",
        vuln_class="vcs-leak",
        expected_severity="medium",
        title_contains=("git config", "git configuration"),
        target_path_contains=("/.git/config",),
    ),
    Expectation(
        description="/.git/HEAD exposed",
        vuln_class="vcs-leak",
        expected_severity="info",
        title_contains=("git", "head"),
        target_path_contains=("/.git/HEAD",),
        known_gap=True,
        known_gap_reason="No high-coverage nuclei template for /.git/HEAD specifically — git-config-disclosure usually fires on /.git/config alone.",
    ),
    Expectation(
        description="/.DS_Store exposed",
        vuln_class="vcs-leak",
        expected_severity="info",
        title_contains=("ds_store", "ds store"),
        target_path_contains=("/.DS_Store",),
    ),

    # ── Secret leaks via .env (nuclei) ──────────────────────────────────
    Expectation(
        description=".env file exposed (generic)",
        vuln_class="secret-leak",
        expected_severity="high",
        title_contains=("env file", "env disclosure", "env-file"),
        target_path_contains=("/.env",),
    ),
    Expectation(
        description=".env contains AWS access key",
        vuln_class="secret-leak",
        expected_severity="high",
        title_contains=("aws", "access key"),
        target_path_contains=("/.env",),
        known_gap=True,
        known_gap_reason="nuclei's generic .env template fires once per URL and doesn't itemise per-secret-class. Needs a per-secret detector (trufflehog / gitleaks / our own) for AWS / Stripe / GitHub PAT / JWT.",
    ),
    Expectation(
        description=".env contains Stripe live secret",
        vuln_class="secret-leak",
        expected_severity="high",
        title_contains=("stripe",),
        target_path_contains=("/.env",),
        known_gap=True,
        known_gap_reason="Per-secret-class detection — same gap as AWS key.",
    ),
    Expectation(
        description=".env contains GitHub personal access token (ghp_)",
        vuln_class="secret-leak",
        expected_severity="high",
        title_contains=("github", "token"),
        target_path_contains=("/.env",),
        known_gap=True,
        known_gap_reason="Per-secret-class detection — same gap as AWS key.",
    ),

    # ── Exposed config files (nuclei) ───────────────────────────────────
    Expectation(
        description="IIS web.config exposed",
        vuln_class="config-leak",
        expected_severity="medium",
        title_contains=("web.config",),
        target_path_contains=("/web.config",),
        known_gap=True,
        known_gap_reason="No high-precision nuclei template fires on a generic web.config disclosure. Needs a custom check or community template.",
    ),
    Expectation(
        description="Apache .htaccess exposed",
        vuln_class="config-leak",
        expected_severity="low",
        title_contains=("htaccess",),
        target_path_contains=("/.htaccess",),
        known_gap=True,
        known_gap_reason="Same pattern — no template ships in the standard set.",
    ),

    # ── Backup files ────────────────────────────────────────────────────
    Expectation(
        description="PHP backup file leak (index.php.bak)",
        vuln_class="backup-leak",
        expected_severity="medium",
        title_contains=("backup", "bak"),
        target_path_contains=("/index.php.bak",),
        known_gap=True,
        known_gap_reason="nuclei's exposed-backups template needs specific naming patterns. Could be augmented by content-discovery (ffuf/dirsearch) which csak doesn't yet run.",
    ),

    # ── Server info / version disclosure ───────────────────────────────
    Expectation(
        # nuclei's apache-server-status template fires once per host
        # even when both /server-status and /server-info exist —
        # which path wins is non-deterministic across runs. Treat as
        # one expectation: as long as csak surfaces the disclosure
        # somewhere, we're good.
        description="Apache server-status / server-info disclosure exposed",
        vuln_class="server-info",
        expected_severity="low",
        title_contains=("apache", "server status", "server info"),
        target_path_contains=("/server-status", "/server-info"),
    ),
    Expectation(
        description="phpinfo() page exposed",
        vuln_class="server-info",
        expected_severity="medium",
        title_contains=("phpinfo",),
        target_path_contains=("/phpinfo.php",),
        known_gap=True,
        known_gap_reason="phpinfo-files template needs content matching. Our fixture has 'PHP Version 5.6.0' which should match but we've seen it not fire reliably in deep mode.",
    ),
    Expectation(
        description="Outdated Apache 2.2.0 fingerprint",
        vuln_class="version-disclosure",
        expected_severity="low",
        title_contains=("apache", "end-of-life", "eol"),
        target_path_contains=("127.0.0.1:8080",),
    ),
    Expectation(
        description="Outdated nginx 1.13.0 fingerprint",
        vuln_class="version-disclosure",
        expected_severity="info",
        title_contains=("nginx", "end-of-life", "eol"),
        target_path_contains=("127.0.0.1:8000",),
    ),

    # ── API discovery (nuclei) ──────────────────────────────────────────
    Expectation(
        description="Swagger / OpenAPI definition exposed",
        vuln_class="api-discovery",
        expected_severity="info",
        title_contains=("swagger", "openapi", "api"),
        target_path_contains=("/swagger.json", "/api-docs"),
        known_gap=True,
        known_gap_reason="exposed-swagger-files template requires 'swagger' string in known location. Our /swagger.json should match but doesn't fire reliably.",
    ),
    Expectation(
        description="GraphQL introspection enabled",
        vuln_class="api-discovery",
        expected_severity="medium",
        title_contains=("graphql", "introspection"),
        target_path_contains=("/graphql",),
        known_gap=True,
        known_gap_reason="graphql-detect template fires only on the playground UI, not the JSON endpoint. Needs an introspection-content-aware check.",
    ),

    # ── CORS misconfig ──────────────────────────────────────────────────
    Expectation(
        description="CORS Access-Control-Allow-Origin: * with credentials",
        vuln_class="cors-misconfig",
        expected_severity="medium",
        title_contains=("cors",),
        target_path_contains=("/graphql",),
        known_gap=True,
        known_gap_reason="No DAST-style CORS probe in the current pipeline — needs a specific tool or a header-pattern matcher we'd have to add.",
    ),

    # ── Cookie security ─────────────────────────────────────────────────
    Expectation(
        description="Session cookie missing Secure/HttpOnly/SameSite",
        vuln_class="cookie-security",
        expected_severity="info",
        title_contains=("cookie",),
        target_path_contains=("127.0.0.1:8080",),
    ),

    # ── Missing security headers ────────────────────────────────────────
    Expectation(
        description="HSTS / CSP / X-Frame-Options missing on app",
        vuln_class="missing-security-headers",
        expected_severity="info",
        title_contains=("strict-transport-security", "content-security-policy",
                        "x-frame-options", "missing security headers"),
        target_path_contains=("127.0.0.1:8080",),
    ),

    # ── Default-credentials basic auth ──────────────────────────────────
    Expectation(
        description="Admin port accepts default basic-auth admin:admin",
        vuln_class="default-credentials",
        expected_severity="high",
        title_contains=("default", "credential", "weak", "basic"),
        target_path_contains=("127.0.0.1:8000",),
        known_gap=True,
        known_gap_reason="default-login templates don't probe arbitrary basic-auth realms unless tagged for specific products (Tomcat, Jenkins). We'd need to either (a) add a generic basic-auth-default-creds tool, or (b) tag the realm so the right template fires.",
    ),

    # ── Open redirect ───────────────────────────────────────────────────
    Expectation(
        description="Open redirect via /redir?next=…",
        vuln_class="open-redirect",
        expected_severity="medium",
        title_contains=("open redirect", "redirect"),
        target_path_contains=("/redir",),
        known_gap=True,
        known_gap_reason="nuclei's generic-open-redirect template requires specific param/path patterns and often misses /redir?next=. Needs DAST-style probing (csak doesn't run a DAST tool).",
    ),

    # ── Reflected XSS ───────────────────────────────────────────────────
    Expectation(
        description="Reflected query parameter on /search?q=…",
        vuln_class="reflected-xss",
        expected_severity="medium",
        title_contains=("reflect", "xss"),
        target_path_contains=("/search",),
        known_gap=True,
        known_gap_reason="DAST-only — needs a fuzzer (dalfox, ffuf with payloads) which isn't in the pipeline.",
    ),

    # ── Findings csak DOES surface that previously had no expectation.
    #    Locking these in so a regression (lost finding) shows up as
    #    a miss rather than going silently undetected. ──────────────────
    Expectation(
        description="PHP End-of-Life detected from app fingerprint",
        vuln_class="version-disclosure",
        expected_severity="info",
        title_contains=("php", "end-of-life", "eol"),
        target_path_contains=("127.0.0.1:8080",),
    ),
    Expectation(
        description="Apache HTTP Server detection (technology fingerprint)",
        vuln_class="tech-detect",
        expected_severity="info",
        title_contains=("apache", "detection", "detect"),
        target_path_contains=("127.0.0.1:8080",),
    ),
    Expectation(
        description="Wappalyzer technology detection on admin port",
        vuln_class="tech-detect",
        expected_severity="info",
        title_contains=("wappalyzer", "technology"),
        target_path_contains=("127.0.0.1:8000",),
    ),
    Expectation(
        description="Basic auth realm detected on admin port",
        vuln_class="auth-detect",
        expected_severity="info",
        title_contains=("basic auth", "auth detection"),
        target_path_contains=("127.0.0.1:8000",),
    ),
    Expectation(
        description="robots.txt exposes sensitive paths",
        vuln_class="info-disclosure",
        expected_severity="info",
        title_contains=("robots",),
        target_path_contains=("/robots.txt",),
    ),
    # NOTE: when scanning 127.0.0.1 nuclei reaches *all* services on
    # the host, including the user's own SMB stack on :445. These
    # findings are csak working correctly — they're host-level, not
    # part of the test target's HTTP surface. Documenting them so the
    # unexpected-findings count stays at zero on a clean run.
    Expectation(
        description="SMB service findings on host (127.0.0.1:445)",
        vuln_class="host-enumeration",
        expected_severity="info",
        title_contains=("smb",),
        target_path_contains=("127.0.0.1:445",),
    ),
)


HEAVY_TARGET = TargetSpec(
    name="heavy",
    description=(
        "Multi-port HTTP target: 'app' on 8080 (broad surface, no auth) "
        "and 'admin' on 8000 (default basic-auth admin:admin). Bound to "
        "127.0.0.1."
    ),
    expectations=_EXPECTATIONS,
    launcher=launch,
)
