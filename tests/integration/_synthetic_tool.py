"""Synthetic CLI tool used by the adaptive-rate end-to-end test.

Invoked by ``Runner`` (via the real ``RealSpawner`` / subprocess.Popen)
exactly the way nuclei would be. Probes a URL ``-u`` over HTTP and:

  * On every 429 response, prints to **stderr** in nuclei's format:
    ``[WRN] [synth-template] Could not execute request for: context deadline exceeded``.
    The Runner's ``detect_rate_limit_signal`` hook on
    :data:`csak.collect.tools.nuclei.NUCLEI` matches that line, so
    repeated 429s drive the adaptive limiter the same way they would
    for real nuclei.
  * On every 200, prints a stats line that matches nuclei's
    ``parse_progress`` regex so the Runner emits ``progress`` events.
  * Writes an empty findings file at ``-o`` and exits 0.

The fake server (started by the test) returns 429 for the first
``--rate-429`` requests, then 200, so we can prove the full loop
"target 429s → tool stderr → Runner halves rate → run completes" in
a real subprocess context.
"""
from __future__ import annotations

import argparse
import sys
import time
import urllib.request
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", required=True, help="target URL")
    parser.add_argument("-o", required=True, help="output findings file")
    parser.add_argument("--probes", type=int, default=8,
                        help="number of HTTP probes to issue")
    args = parser.parse_args()

    Path(args.o).parent.mkdir(parents=True, exist_ok=True)
    Path(args.o).write_text("", encoding="utf-8")

    errors = 0
    for i in range(args.probes):
        try:
            with urllib.request.urlopen(args.u, timeout=2) as resp:
                _ = resp.read()
            status = 200
        except urllib.error.HTTPError as e:
            status = e.code
        except Exception:
            status = 0

        if status == 429:
            errors += 1
            # Match a spec-defined rate-limit indicator. The runner's
            # ``detect_rate_limit_signal`` looks for "429" / "503" /
            # "rate limit" / "too many requests" / "retry-after" in
            # [WRN]/[ERR] lines. Real nuclei surfaces these when the
            # upstream returns 429 with a Retry-After header.
            print(
                f"[WRN] [synth-template-{i}] "
                f"got HTTP 429 Too Many Requests from {args.u} (retry-after: 1s)",
                file=sys.stderr,
                flush=True,
            )
        else:
            # Emit a stats line in nuclei's format every probe so the
            # progress regex picks it up. Format from nuclei.py:_STATS_RE:
            #   Stats: requests=N errors=M RPS=R percent=P
            print(
                f"[INF] Stats: requests={i + 1} errors={errors} "
                f"RPS=10 percent={int((i + 1) / args.probes * 100)}",
                file=sys.stderr,
                flush=True,
            )
        time.sleep(0.05)

    return 0


if __name__ == "__main__":
    sys.exit(main())
