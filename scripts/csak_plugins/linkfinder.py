"""Plugin: ``linkfinder`` — a working URL extractor that drives recursion.

Why this exists: nuclei's recursion behavior depends on which of its
templates fire and which extractors they carry. That's fine for real
scans but makes slice 3's recursion hard to demo deterministically
against a synthetic test target. ``linkfinder`` is a stand-in that
ALWAYS produces typed URL outputs from any URL it scans, by parsing
HTML ``<a href>`` and sitemap ``<loc>`` and JSON string fields.

It's also an example of a fully-functional plugin you can copy and
modify. The binary is ``python`` (cross-platform, no install) so the
helper runs as a subprocess from within the same venv — no separate
``go install`` or ``pip install`` dance.

Once loaded, ``linkfinder``::

  * accepts ``url`` and ``host`` (widens to domain/subdomain)
  * produces ``url``
  * fetches the target with stdlib ``urllib``, extracts links
  * writes one URL per line as JSONL to its artifact
  * ``extract_outputs`` reads the JSONL and yields ``TypedTarget(url=...)``

In a recursive collect against the test target, linkfinder's depth-0
output (URLs from sitemap.xml, robots.txt, HTML) feeds nuclei at
depth 1 — which then probes paths nuclei wouldn't have known about
from httpx alone.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from csak.collect.tool import Mode, RateLimitDefaults, Tool
from csak.collect.tools import register_tool
from csak.collect.types import InvalidTargetError, TypedTarget, classify
from csak.ingest.parser import ParsedScan, ParseResult
from csak.ingest.pipeline import register_parser


_RUNNER = Path(__file__).parent / "_linkfinder_runner.py"


class LinkfinderTool(Tool):
    name = "linkfinder"
    binary = sys.executable        # current python interpreter
    minimum_version = "3.10.0"
    install_command = "no install needed — uses the active Python interpreter"
    output_filename = "links.jsonl"
    rate_limit = None  # the helper paces itself

    # Same accepts as httpx (host) plus url so we can run on URL-typed
    # candidates that bypass httpx. produces=["url"] feeds nuclei.
    accepts = ["host", "url"]
    produces = ["url"]

    def parse_version(self, output: str) -> str | None:
        # ``python --version`` prints ``Python 3.X.Y``. Extract the
        # version. ``-version`` (the slice 2 default for httpx/nuclei)
        # would be a syntax error for python; override version_args.
        import re

        match = re.search(r"(\d+\.\d+\.\d+)", output)
        return match.group(1) if match else None

    version_args = ("--version",)

    def invocation(
        self,
        *,
        target: str,
        target_type: str,
        mode: Mode,
        input_file: str | None,
        output_file: str,
        overrides: dict[str, str] | None = None,
    ) -> list[str]:
        argv: list[str] = [str(_RUNNER), "--output", output_file]
        if input_file:
            argv.extend(["--input", input_file])
        else:
            argv.extend(["--target", target])
        # ``deep`` mode crawls one extra hop. ``quick`` does just the
        # root URL. Keep it simple for the demo.
        if mode == "deep":
            argv.append("--depth=2")
        elif mode == "quick":
            argv.append("--depth=1")
        else:
            argv.append("--depth=1")
        return argv

    def extract_outputs(self, artifact_path, scan):
        out: list[TypedTarget] = []
        if artifact_path is None:
            return out
        path = Path(artifact_path)
        if not path.exists():
            return out
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            return out
        for raw in text.splitlines():
            raw = raw.strip()
            if not raw:
                continue
            try:
                row = json.loads(raw)
            except json.JSONDecodeError:
                continue
            url = row.get("url")
            if not url:
                continue
            try:
                t = classify(str(url))
            except InvalidTargetError:
                continue
            if t.type != "url":
                # The helper's intent is URLs; if the value classifies
                # as something else (e.g. a bare host extracted from a
                # JSON field), skip — nuclei already handles bare hosts
                # via the existing routes.
                continue
            t.metadata["source"] = row.get("source", "linkfinder")
            out.append(t)
        return out


def _linkfinder_parser(path: Path) -> ParseResult:
    """Tiny ingest parser so the slice 1 pipeline accepts linkfinder
    artifacts cleanly.

    linkfinder doesn't surface vulnerabilities — its job is to feed
    the recursion frontier via ``extract_outputs``. We emit a
    ParsedScan with no findings and no discovered identifiers; the
    Scan row records the artifact's existence and ``Scan.notes``
    explains it via the collect pipeline.

    Plugins that *do* find vulnerabilities should write a richer
    parser (see ``csak/ingest/nuclei.py`` for the canonical shape).
    """
    now = datetime.now(timezone.utc)
    return ParseResult(
        scan=ParsedScan(
            source_tool="linkfinder",
            label=f"linkfinder {now.strftime('%Y-%m-%dT%H-%M-%S')}",
            scan_started_at=now,
            scan_completed_at=now,
            timestamp_source="fallback-ingested",
            notes="linkfinder discovery artifact",
        ),
        findings=[],
    )


register_parser("linkfinder", _linkfinder_parser)
register_tool(LinkfinderTool(), origin="plugin", source_path=__file__)
