"""End-to-end test for adaptive rate limiting.

Per slice 2 spec §exit-criteria: *"Adaptive rate limiting kicks in on
a target that returns 429s … verifiable with a synthetic test against
a rate-limited endpoint."*

Existing runner tests verify ``detect_rate_limit_signal`` against
canned stderr (``test_runner_adaptive_rate_kicks_in_on_repeated_signals``).
This test closes the loop: a real HTTP server returns 429s, a real
Python subprocess (via :class:`RealSpawner`) probes it and prints the
matching nuclei-style stderr, the real :class:`Runner` reads that
stderr through ``subprocess.PIPE`` and halves the rate. No fakes in
the rate-limit detection path.
"""
from __future__ import annotations

import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Iterator

import pytest

from csak.collect import runner as runner_mod
from csak.collect.runner import RunEvent, Runner
from csak.collect.tools.nuclei import NucleiTool


_SYNTH_TOOL = Path(__file__).parent / "integration" / "_synthetic_tool.py"


# ---------------------------------------------------------------------------
# 429-returning HTTP server
# ---------------------------------------------------------------------------


class _RateLimitedHandler(BaseHTTPRequestHandler):
    """Returns 429 for the first ``THRESHOLD`` requests, 200 thereafter."""

    THRESHOLD: int = 6
    _count_lock = threading.Lock()
    _count: int = 0

    @classmethod
    def reset(cls) -> None:
        with cls._count_lock:
            cls._count = 0

    def do_GET(self) -> None:  # noqa: N802 — stdlib API
        with self._count_lock:
            self.__class__._count += 1
            n = self.__class__._count
        if n <= self.THRESHOLD:
            self.send_response(429)
            self.send_header("Retry-After", "1")
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        return


@pytest.fixture
def rate_limited_target() -> Iterator[str]:
    _RateLimitedHandler.reset()
    server = ThreadingHTTPServer(("127.0.0.1", 0), _RateLimitedHandler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{port}/"
    finally:
        server.shutdown()


# ---------------------------------------------------------------------------
# A real Tool subclass that invokes our synthetic script with the
# nuclei rate-limit signal detector — so the runner's signal-matching
# code runs unchanged.
# ---------------------------------------------------------------------------


class _SyntheticTool(NucleiTool):
    """Reuses NucleiTool's rate-signal regex / progress regex but
    invokes the synthetic Python script instead of the nuclei binary.

    ``binary`` is the live Python interpreter — the Runner uses it
    both for ``shutil.which`` and as ``argv[0]`` of the subprocess,
    so the script gets executed directly without a shim binary."""

    name = "synthetic"
    binary = sys.executable

    def applies_to(self, target_type: str) -> bool:  # type: ignore[override]
        return True

    def is_skipped_by_mode(self, mode: str) -> bool:  # type: ignore[override]
        return False

    def invocation(
        self,
        *,
        target: str,
        target_type: str,
        mode: str,
        input_file: str | None,
        output_file: str,
        overrides: dict[str, str] | None = None,
    ) -> list[str]:  # type: ignore[override]
        return [
            str(_SYNTH_TOOL),
            "-u", target,
            "-o", output_file,
            "--probes", "10",
        ]


# ---------------------------------------------------------------------------
# The end-to-end test
# ---------------------------------------------------------------------------


def test_adaptive_rate_loop_against_real_429_target(
    tmp_path: Path,
    rate_limited_target: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Real HTTP server → real subprocess → real Runner. Asserts the
    rate-adjusted event fires and the run completes successfully when
    the target returns 429s."""
    events: list[RunEvent] = []
    runner = Runner(progress_callback=events.append, adaptive_rate=True)

    result = runner.run_tool(
        tool=_SyntheticTool(),
        target=rate_limited_target,
        target_type="url",
        mode="standard",
        input_path=None,
        output_dir=tmp_path / "synth",
        timeout=30.0,
    )

    rate_signals = [e for e in events if e.kind == "rate_signal"]
    rate_adjusted = [e for e in events if e.kind == "rate_adjusted"]

    # The target returned 6 × 429s; the synthetic tool printed 6
    # rate-limit stderr lines; the runner needs ≥ 3 to halve.
    assert len(rate_signals) >= 3, (
        f"expected at least 3 rate signals from real 429s, got {len(rate_signals)}; "
        f"events: {[e.kind for e in events]}"
    )
    assert len(rate_adjusted) >= 1, (
        "expected the runner to emit a rate_adjusted event after the threshold"
    )

    adj = rate_adjusted[0]
    assert adj.rate_after is not None and adj.rate_before is not None
    assert adj.rate_after == adj.rate_before // 2

    # The run must complete cleanly (the spec requires that adaptive
    # rate keeps the scan going, not that it aborts).
    assert result.status == "succeeded"
    assert result.adjusted_rate == adj.rate_after
