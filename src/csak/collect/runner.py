"""Subprocess runner with adaptive rate limiting and live progress.

One ``run_tool`` call:
  1. Builds the input file (if upstream produced one) and the output
     file (always).
  2. Invokes the tool's binary as a subprocess.
  3. Reads stderr line by line, calling ``parse_progress`` and
     ``detect_rate_limit_signal`` per line.
  4. Polls the output file at intervals to count produced rows for
     tools that don't expose a percent (subfinder).
  5. Emits ``RunEvent`` instances to the optional progress callback,
     so the CLI can render a live progress bar / count.
  6. Tracks rate-limit signal threshold; when 3+ signals appear
     within ``RATE_WINDOW_SEC`` the runner halves the active rate flag
     for the *next* invocation of this tool and emits a
     ``rate_adjusted`` event. Slice 2 doesn't restart the running
     subprocess — that requires SIGUSR1 support most ProjectDiscovery
     tools don't expose. The signal still surfaces to the analyst.
  7. Returns a ``RunResult``: exit code, output path, line count,
     elapsed, list of events seen, error message on failure.

The runner deliberately doesn't know about Artifacts, Scans, or the
ingest pipeline — its caller (``csak.collect.pipeline``) wires those
in. This module is a pure subprocess+IO wrapper, easy to unit-test by
substituting a fake ``Spawner``.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Protocol

from csak.collect.tool import Mode, ProgressUpdate, TargetType, Tool


RATE_WINDOW_SEC: float = 30.0
RATE_SIGNAL_THRESHOLD: int = 3
POLL_INTERVAL_SEC: float = 0.5


@dataclass
class RunEvent:
    """Notable thing that happened during a tool invocation.

    The CLI's progress reporter consumes these. Tests assert on them.
    """

    kind: str   # "started" | "progress" | "rate_signal" | "rate_adjusted"
                # | "completed" | "failed" | "timeout"
    tool: str
    elapsed: float = 0.0
    progress: ProgressUpdate | None = None
    message: str | None = None
    rate_before: int | None = None
    rate_after: int | None = None


@dataclass
class RunResult:
    tool: str
    status: str          # "succeeded" | "failed" | "timeout" | "skipped"
    output_path: Path | None
    output_line_count: int = 0
    exit_code: int | None = None
    elapsed: float = 0.0
    events: list[RunEvent] = field(default_factory=list)
    error: str | None = None
    started_at: float = 0.0
    completed_at: float = 0.0
    # If the adaptive limiter halved the rate during the run, this is
    # the new value. The pipeline persists it on the Tool instance for
    # subsequent invocations within the same collect run.
    adjusted_rate: int | None = None


ProgressCallback = Callable[[RunEvent], None]


class Spawner(Protocol):
    """Subprocess factory the runner uses. Production code uses
    ``RealSpawner`` (subprocess.Popen). Tests substitute a fake.
    """

    def spawn(
        self,
        argv: list[str],
        *,
        cwd: Path | None,
    ) -> "RunningProcess": ...


class RunningProcess(Protocol):
    """Minimal interface a spawned process must support."""

    def stderr_lines(self) -> Iterable[str]: ...
    def wait(self, timeout: float | None) -> int: ...
    def terminate(self) -> None: ...
    @property
    def pid(self) -> int: ...


class RealSpawner:
    """Production spawner: subprocess.Popen with text-mode stderr."""

    def spawn(
        self,
        argv: list[str],
        *,
        cwd: Path | None,
    ) -> RunningProcess:
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,    # nuclei exits 1 if stdin is the inherited console on Windows
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            cwd=cwd,
            bufsize=1,  # line-buffered
        )
        return _PopenAdapter(proc)


class _PopenAdapter:
    def __init__(self, proc: subprocess.Popen[str]) -> None:
        self._proc = proc

    def stderr_lines(self) -> Iterable[str]:
        assert self._proc.stderr is not None
        for raw in self._proc.stderr:
            yield raw.rstrip("\r\n")

    def wait(self, timeout: float | None) -> int:
        return self._proc.wait(timeout=timeout)

    def terminate(self) -> None:
        try:
            self._proc.terminate()
        except ProcessLookupError:
            pass

    @property
    def pid(self) -> int:
        return self._proc.pid


class Runner:
    """Stateful per-collect-run subprocess wrapper.

    The runner accumulates rate-limit signals across the whole run so
    that adaptive halving applies cumulatively to subsequent tools.
    """

    def __init__(
        self,
        *,
        spawner: Spawner | None = None,
        progress_callback: ProgressCallback | None = None,
        adaptive_rate: bool = True,
    ) -> None:
        self._spawner = spawner or RealSpawner()
        self._on_event = progress_callback or (lambda e: None)
        self._adaptive = adaptive_rate

    def run_tool(
        self,
        *,
        tool: Tool,
        target: str,
        target_type: TargetType,
        mode: Mode,
        input_path: Path | None,
        output_dir: Path,
        overrides: dict[str, str] | None = None,
        timeout: float | None = None,
    ) -> RunResult:
        """Execute one tool. Returns a fully-populated RunResult.

        Failures (binary missing, non-zero exit, timeout) are caught
        and recorded on the result — not raised — so the caller can
        keep the pipeline running per spec §Pipeline shape.
        """
        if not shutil.which(tool.binary):
            return RunResult(
                tool=tool.name,
                status="failed",
                output_path=None,
                error=(
                    f"binary {tool.binary!r} not found on PATH; "
                    f"run `csak doctor` to install"
                ),
            )

        output_dir.mkdir(parents=True, exist_ok=True)
        output_file = output_dir / tool.output_filename

        argv = [tool.binary, *tool.invocation(
            target=target,
            target_type=target_type,
            mode=mode,
            input_file=str(input_path) if input_path else None,
            output_file=str(output_file),
            overrides=overrides,
        )]

        # Reset per-run state on the tool instance (httpx/nuclei track
        # rolling error counts — see their parse_progress impls).
        if hasattr(tool, "_last_errors"):
            setattr(tool, "_last_errors", 0)

        result = RunResult(
            tool=tool.name,
            status="failed",
            output_path=output_file,
            started_at=time.monotonic(),
        )
        self._emit(result, RunEvent(kind="started", tool=tool.name, elapsed=0.0))

        proc = None
        rate_signal_times: list[float] = []
        current_rate = self._initial_rate(tool)

        try:
            proc = self._spawner.spawn(argv, cwd=None)
            deadline = (
                time.monotonic() + timeout if timeout is not None else None
            )
            for line in proc.stderr_lines():
                now = time.monotonic()
                if deadline is not None and now > deadline:
                    proc.terminate()
                    result.status = "timeout"
                    result.error = (
                        f"stage exceeded timeout of {timeout:.0f}s; "
                        f"partial output captured"
                    )
                    self._emit(
                        result,
                        RunEvent(
                            kind="timeout",
                            tool=tool.name,
                            elapsed=now - result.started_at,
                            message=result.error,
                        ),
                    )
                    break

                self._handle_line(
                    tool=tool,
                    line=line,
                    result=result,
                    rate_signal_times=rate_signal_times,
                    current_rate=[current_rate],
                    started=result.started_at,
                )

            # Drain remainder + final wait. The for-loop above exits
            # when stderr closes (process exited or terminated).
            try:
                exit_code = proc.wait(
                    timeout=max(0.0, deadline - time.monotonic())
                    if deadline is not None
                    else None
                )
            except subprocess.TimeoutExpired:
                proc.terminate()
                exit_code = -1
                result.status = "timeout"
                result.error = (
                    f"stage exceeded timeout of {timeout:.0f}s; "
                    f"partial output captured"
                )

            result.exit_code = exit_code
            result.completed_at = time.monotonic()
            result.elapsed = result.completed_at - result.started_at
            result.output_line_count = _count_lines(output_file)

            if result.status == "timeout":
                # Already labeled.
                pass
            elif exit_code == 0:
                result.status = "succeeded"
                self._emit(
                    result,
                    RunEvent(
                        kind="completed",
                        tool=tool.name,
                        elapsed=result.elapsed,
                        message=f"{result.output_line_count} rows",
                    ),
                )
            else:
                result.status = "failed"
                result.error = result.error or (
                    f"{tool.binary} exited with code {exit_code}"
                )
                self._emit(
                    result,
                    RunEvent(
                        kind="failed",
                        tool=tool.name,
                        elapsed=result.elapsed,
                        message=result.error,
                    ),
                )

            # If we adjusted the rate during this run, surface the
            # most recent rate on the result so the next stage's
            # invocation can carry the lowered ceiling forward.
            for ev in result.events:
                if ev.kind == "rate_adjusted" and ev.rate_after is not None:
                    result.adjusted_rate = ev.rate_after

        except FileNotFoundError as e:
            # shutil.which lied (rare — race condition on PATH).
            result.status = "failed"
            result.error = f"failed to launch {tool.binary}: {e}"
            result.completed_at = time.monotonic()
            result.elapsed = result.completed_at - result.started_at
            self._emit(
                result,
                RunEvent(
                    kind="failed",
                    tool=tool.name,
                    elapsed=result.elapsed,
                    message=result.error,
                ),
            )
        except KeyboardInterrupt:
            # Per spec §Mitigations: SIGTERM the current stage,
            # capture partial output, mark failed, propagate to the
            # caller so the pipeline aborts cleanly.
            if proc is not None:
                proc.terminate()
            result.status = "failed"
            result.error = "interrupted by user (Ctrl-C)"
            result.completed_at = time.monotonic()
            result.elapsed = result.completed_at - result.started_at
            result.output_line_count = _count_lines(output_file)
            self._emit(
                result,
                RunEvent(
                    kind="failed",
                    tool=tool.name,
                    elapsed=result.elapsed,
                    message=result.error,
                ),
            )
            raise

        return result

    def _handle_line(
        self,
        *,
        tool: Tool,
        line: str,
        result: RunResult,
        rate_signal_times: list[float],
        current_rate: list[int | None],
        started: float,
    ) -> None:
        progress = tool.parse_progress(line)
        if progress is not None:
            self._emit(
                result,
                RunEvent(
                    kind="progress",
                    tool=tool.name,
                    elapsed=time.monotonic() - started,
                    progress=progress,
                ),
            )

        if not self._adaptive or tool.rate_limit is None:
            return

        if not tool.detect_rate_limit_signal(line):
            return

        now = time.monotonic()
        rate_signal_times.append(now)
        # Drop signals outside the rolling window.
        cutoff = now - RATE_WINDOW_SEC
        rate_signal_times[:] = [t for t in rate_signal_times if t >= cutoff]

        self._emit(
            result,
            RunEvent(
                kind="rate_signal",
                tool=tool.name,
                elapsed=now - started,
                message=line.strip(),
            ),
        )

        if len(rate_signal_times) >= RATE_SIGNAL_THRESHOLD:
            previous = current_rate[0] if current_rate[0] is not None else (
                tool.rate_limit.start_rps
            )
            new_rate = max(tool.rate_limit.floor_rps, previous // 2 if previous else 0)
            if new_rate != previous and new_rate > 0:
                current_rate[0] = new_rate
                self._emit(
                    result,
                    RunEvent(
                        kind="rate_adjusted",
                        tool=tool.name,
                        elapsed=now - started,
                        rate_before=previous,
                        rate_after=new_rate,
                        message=(
                            f"detected rate limiting, reducing to "
                            f"{new_rate} req/s"
                        ),
                    ),
                )
                # Reset the signal queue so we wait for fresh evidence
                # before halving again.
                rate_signal_times.clear()

    def _initial_rate(self, tool: Tool) -> int | None:
        if tool.rate_limit is None:
            return None
        return tool.rate_limit.start_rps if tool.rate_limit.start_rps > 0 else None

    def _emit(self, result: RunResult, event: RunEvent) -> None:
        result.events.append(event)
        try:
            self._on_event(event)
        except Exception:
            # Progress callback failures must not kill the run.
            pass


def _count_lines(path: Path) -> int:
    """Cheap row count for JSONL outputs. Returns 0 if the file is
    missing or unreadable.
    """
    try:
        if not path.exists():
            return 0
        n = 0
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(64 * 1024), b""):
                n += chunk.count(b"\n")
        return n
    except OSError:
        return 0


def make_input_file_for(target: str, dest: Path) -> Path:
    """Write a one-line input file containing ``target``.

    Used when a stage needs ``-l <file>`` but no upstream artifact
    exists — e.g., httpx running directly against a CIDR or a single
    IP target. Returns the path written.
    """
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(target + "\n", encoding="utf-8")
    return dest


def discover_binary(tool: Tool) -> str | None:
    """Return the absolute path to ``tool.binary`` on PATH, or None."""
    found = shutil.which(tool.binary)
    return os.fspath(found) if found else None
