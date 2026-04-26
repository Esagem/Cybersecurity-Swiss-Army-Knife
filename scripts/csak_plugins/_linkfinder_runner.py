"""Subprocess helper invoked by the ``linkfinder`` plugin.

Spawned as ``python _linkfinder_runner.py --target <url|host> --output
<file>``. Fetches the target (and optionally one hop deeper for
``--depth=2``), extracts URLs from response bodies, and writes one
``{"url": "...", "source": "..."}`` JSONL row per discovered link.

Stdlib only so it runs in any CSAK environment without adding
dependencies. Kept narrow: HTML <a href>, sitemap <loc>, plus any
http/https string in JSON or text bodies. Good enough for the slice
3 recursion demo against the test target.

The leading underscore in the filename keeps the plugin loader from
importing this file as a plugin (``csak.collect.plugins`` skips
``_*.py`` for exactly this reason).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
import urllib.error
from pathlib import Path
from urllib.parse import urlparse, urljoin


_HREF_RE = re.compile(r"""<a[^>]+href=["']([^"'#]+)""", re.IGNORECASE)
_LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.IGNORECASE)
_URL_RE = re.compile(r'https?://[^\s"\'<>]+')


def _normalise(target: str) -> str:
    """Accept ``127.0.0.1`` / ``127.0.0.1:8080`` / ``http://...`` and
    return a fully-qualified URL.
    """
    if "://" in target:
        return target
    return f"http://{target}"


def _fetch(url: str, timeout: float = 5.0) -> tuple[int, str, str]:
    """Return (status, content_type, body_text). Raises only on
    truly catastrophic errors — HTTP errors and connection failures
    are caught and reported via status=0.
    """
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "csak-linkfinder/0.1"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            ctype = resp.headers.get("Content-Type", "")
            raw = resp.read(256 * 1024)  # cap response body
            return resp.status, ctype, raw.decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return e.code, e.headers.get("Content-Type", "") if e.headers else "", body
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return 0, "", f"<fetch failed: {e}>"


def _extract(base_url: str, body: str) -> list[str]:
    """Extract URLs from a response body. Resolves relative paths
    against ``base_url``. De-duplicates inside this single response.
    """
    seen: set[str] = set()
    out: list[str] = []

    def _add(candidate: str) -> None:
        # Resolve relative; fragments/query stripping is intentional —
        # we don't want every ?q=... permutation in the frontier.
        try:
            full = urljoin(base_url, candidate)
        except ValueError:
            return
        if full.startswith(("http://", "https://")):
            full = full.split("#", 1)[0]
            if full not in seen:
                seen.add(full)
                out.append(full)

    for match in _HREF_RE.finditer(body):
        _add(match.group(1))
    for match in _LOC_RE.finditer(body):
        _add(match.group(1))
    for match in _URL_RE.finditer(body):
        _add(match.group(0))
    return out


def _write_results(rows: list[dict], dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")


def main() -> None:
    ap = argparse.ArgumentParser(description="csak linkfinder runner")
    ap.add_argument("--target", help="single URL or host to crawl")
    ap.add_argument("--input", help="newline-separated list of targets")
    ap.add_argument("--output", required=True, help="JSONL output path")
    ap.add_argument("--depth", type=int, default=1, help="hops to follow (1 or 2)")
    ap.add_argument("--max-pages", type=int, default=20)
    ap.add_argument(
        "--scope",
        default="seed-host",
        choices=("seed-host", "any"),
        help=(
            "``seed-host`` (default) emits only URLs whose authority matches "
            "the seed's host[:port], keeping recursive collect bounded to "
            "the in-scope target. ``any`` emits every URL it sees, useful "
            "when you trust the seed not to point off-host."
        ),
    )
    args = ap.parse_args()

    seeds: list[str] = []
    if args.target:
        seeds.append(_normalise(args.target))
    if args.input:
        text = Path(args.input).read_text(encoding="utf-8")
        seeds.extend(_normalise(s.strip()) for s in text.splitlines() if s.strip())

    # Compute the in-scope authority set up front so every fetched
    # response is filtered against it, not just the seeds.
    in_scope: set[str] = set()
    if args.scope == "seed-host":
        for s in seeds:
            parsed = urlparse(s)
            if parsed.hostname:
                netloc = parsed.hostname.lower()
                if parsed.port:
                    netloc += f":{parsed.port}"
                in_scope.add(netloc)
    # Always probe a handful of well-known discovery files when we
    # have a host-shaped seed but no path. Keeps the demo lively.
    discovery_paths = ("/", "/robots.txt", "/sitemap.xml", "/.well-known/security.txt")
    expanded: list[str] = []
    for s in seeds:
        parsed = urlparse(s)
        if not parsed.path or parsed.path == "/":
            for p in discovery_paths:
                expanded.append(s.rstrip("/") + p)
        else:
            expanded.append(s)

    def _in_scope(url: str) -> bool:
        if not in_scope:
            return True
        parsed = urlparse(url)
        if not parsed.hostname:
            return False
        netloc = parsed.hostname.lower()
        if parsed.port:
            netloc += f":{parsed.port}"
        return netloc in in_scope

    rows: list[dict] = []
    queued: list[str] = list(dict.fromkeys(expanded))  # preserve order, dedup
    visited: set[str] = set()
    pages = 0

    for hop in range(max(1, args.depth)):
        next_queued: list[str] = []
        for url in queued:
            if pages >= args.max_pages:
                break
            if url in visited:
                continue
            visited.add(url)
            pages += 1
            status, ctype, body = _fetch(url)
            if status == 0:
                continue
            for link in _extract(url, body):
                if not _in_scope(link):
                    continue
                rows.append({"url": link, "source": url})
                if hop + 1 < args.depth and link not in visited:
                    next_queued.append(link)
        queued = next_queued

    _write_results(rows, Path(args.output))
    sys.stderr.write(
        f"linkfinder: {len(rows)} links from {len(visited)} pages "
        f"(scope={args.scope}{', ' + ','.join(sorted(in_scope)) if in_scope else ''})\n"
    )


if __name__ == "__main__":
    main()
