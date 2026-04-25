"""Runner tests using a fake Spawner.

The Runner is the only thing that touches subprocess; tests inject a
``FakeSpawner`` that returns a ``FakeProcess`` with predetermined
stderr lines and exit code, plus optionally writes a fake output file
to simulate the tool. ``shutil.which`` is monkeypatched to return a
path so the runner doesn't bail at the binary check.
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterable

import pytest

from csak.collect import runner as runner_mod
from csak.collect.runner import RunEvent, Runner
from csak.collect.tools.httpx import HTTPX
from csak.collect.tools.nuclei import NUCLEI
from csak.collect.tools.subfinder import SUBFINDER


class FakeProcess:
    def __init__(
        self,
        *,
        stderr_lines: list[str],
        exit_code: int,
        write_output: tuple[Path, str] | None = None,
    ) -> None:
        self._lines = stderr_lines
        self._exit_code = exit_code
        self._write_output = write_output
        self.terminated = False

    def stderr_lines(self) -> Iterable[str]:
        for line in self._lines:
            yield line
        if self._write_output is not None:
            path, content = self._write_output
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")

    def wait(self, timeout: float | None) -> int:
        return self._exit_code

    def terminate(self) -> None:
        self.terminated = True

    @property
    def pid(self) -> int:
        return 1234


class FakeSpawner:
    def __init__(self, build_process) -> None:
        self._build = build_process
        self.calls: list[list[str]] = []

    def spawn(self, argv: list[str], *, cwd: Path | None) -> FakeProcess:
        self.calls.append(argv)
        return self._build(argv)


@pytest.fixture(autouse=True)
def _fake_which(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pretend every tool is installed."""
    monkeypatch.setattr(runner_mod.shutil, "which", lambda b: f"/usr/bin/{b}")


def test_runner_records_started_and_completed_events(tmp_path: Path) -> None:
    output = tmp_path / "subfinder" / "subdomains.jsonl"

    spawner = FakeSpawner(
        lambda argv: FakeProcess(
            stderr_lines=[],
            exit_code=0,
            write_output=(output, '{"host":"a.acme.com"}\n{"host":"b.acme.com"}\n'),
        )
    )
    events: list[RunEvent] = []
    runner = Runner(spawner=spawner, progress_callback=events.append)

    result = runner.run_tool(
        tool=SUBFINDER,
        target="acme.com",
        target_type="domain",
        mode="standard",
        input_path=None,
        output_dir=tmp_path / "subfinder",
    )

    assert result.status == "succeeded"
    assert result.output_line_count == 2
    assert result.exit_code == 0
    kinds = [e.kind for e in events]
    assert kinds[0] == "started"
    assert kinds[-1] == "completed"
    # Argv should include -d and the target.
    argv = spawner.calls[0]
    assert "-d" in argv
    assert "acme.com" in argv


def test_runner_failed_exit_code_is_recorded(tmp_path: Path) -> None:
    spawner = FakeSpawner(
        lambda argv: FakeProcess(stderr_lines=["[ERR] something broke"], exit_code=1)
    )
    runner = Runner(spawner=spawner)

    result = runner.run_tool(
        tool=SUBFINDER,
        target="acme.com",
        target_type="domain",
        mode="standard",
        input_path=None,
        output_dir=tmp_path / "out",
    )
    assert result.status == "failed"
    assert result.exit_code == 1
    assert result.error is not None
    assert any(e.kind == "failed" for e in result.events)


def test_runner_handles_missing_binary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(runner_mod.shutil, "which", lambda b: None)
    runner = Runner(spawner=FakeSpawner(lambda argv: pytest.fail("should not spawn")))

    result = runner.run_tool(
        tool=SUBFINDER,
        target="acme.com",
        target_type="domain",
        mode="standard",
        input_path=None,
        output_dir=tmp_path / "out",
    )
    assert result.status == "failed"
    assert "subfinder" in (result.error or "")


def test_runner_progress_events_for_httpx_stats(tmp_path: Path) -> None:
    output = tmp_path / "httpx" / "live.jsonl"
    spawner = FakeSpawner(
        lambda argv: FakeProcess(
            stderr_lines=[
                "[INF] Stats: 50/100 (50%) | RPS: 30 | Errors: 2 | Duration: 5s",
                "[INF] Stats: 100/100 (100%) | RPS: 30 | Errors: 2 | Duration: 10s",
            ],
            exit_code=0,
            write_output=(output, '{"url":"https://acme.com","status_code":200}\n'),
        )
    )
    events: list[RunEvent] = []
    runner = Runner(spawner=spawner, progress_callback=events.append)

    runner.run_tool(
        tool=HTTPX,
        target="acme.com",
        target_type="domain",
        mode="standard",
        input_path=None,
        output_dir=tmp_path / "httpx",
    )

    progress_events = [e for e in events if e.kind == "progress"]
    assert len(progress_events) == 2
    assert progress_events[0].progress.percent == 50
    assert progress_events[1].progress.percent == 100


def test_runner_adaptive_rate_kicks_in_on_repeated_signals(tmp_path: Path) -> None:
    """Three rate-limit signals within the window halve the rate."""
    output = tmp_path / "nuclei" / "findings.jsonl"
    stderr = [
        "[WRN] [cve-x] Could not execute request for: context deadline exceeded",
        "[WRN] [cve-y] Could not execute request for: context deadline exceeded",
        "[WRN] [cve-z] Could not execute request for: context deadline exceeded",
        "[WRN] [cve-q] connection refused",
    ]
    spawner = FakeSpawner(
        lambda argv: FakeProcess(
            stderr_lines=stderr,
            exit_code=0,
            write_output=(output, ""),
        )
    )
    events: list[RunEvent] = []
    runner = Runner(spawner=spawner, progress_callback=events.append)

    result = runner.run_tool(
        tool=NUCLEI,
        target="acme.com",
        target_type="domain",
        mode="standard",
        input_path=None,
        output_dir=tmp_path / "nuclei",
    )

    rate_signals = [e for e in events if e.kind == "rate_signal"]
    rate_adjusted = [e for e in events if e.kind == "rate_adjusted"]
    assert len(rate_signals) >= 3
    assert len(rate_adjusted) == 1
    adj = rate_adjusted[0]
    assert adj.rate_after is not None
    assert adj.rate_before is not None
    assert adj.rate_after == adj.rate_before // 2
    assert result.adjusted_rate == adj.rate_after


def test_runner_adaptive_rate_disabled_does_not_emit_adjustment(
    tmp_path: Path,
) -> None:
    spawner = FakeSpawner(
        lambda argv: FakeProcess(
            stderr_lines=[
                "[WRN] [a] context deadline exceeded",
                "[WRN] [b] context deadline exceeded",
                "[WRN] [c] context deadline exceeded",
            ],
            exit_code=0,
            write_output=(tmp_path / "nuclei" / "findings.jsonl", ""),
        )
    )
    events: list[RunEvent] = []
    runner = Runner(spawner=spawner, progress_callback=events.append, adaptive_rate=False)
    runner.run_tool(
        tool=NUCLEI,
        target="acme.com",
        target_type="domain",
        mode="standard",
        input_path=None,
        output_dir=tmp_path / "nuclei",
    )
    assert not any(e.kind == "rate_adjusted" for e in events)
    assert not any(e.kind == "rate_signal" for e in events)


def test_runner_propagates_keyboard_interrupt(tmp_path: Path) -> None:
    class InterruptingProcess(FakeProcess):
        def stderr_lines(self) -> Iterable[str]:
            yield "[INF] starting"
            raise KeyboardInterrupt

    spawner = FakeSpawner(
        lambda argv: InterruptingProcess(stderr_lines=[], exit_code=130)
    )
    runner = Runner(spawner=spawner)

    with pytest.raises(KeyboardInterrupt):
        runner.run_tool(
            tool=SUBFINDER,
            target="acme.com",
            target_type="domain",
            mode="standard",
            input_path=None,
            output_dir=tmp_path / "out",
        )


def test_make_input_file_for_writes_target(tmp_path: Path) -> None:
    dest = tmp_path / "input.txt"
    out = runner_mod.make_input_file_for("10.0.0.0/24", dest)
    assert out == dest
    assert dest.read_text() == "10.0.0.0/24\n"
