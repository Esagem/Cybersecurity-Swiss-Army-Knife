from pathlib import Path

from click.testing import CliRunner

from csak.cli.main import main


def _invoke(args: list[str], tmp_path: Path):
    runner = CliRunner()
    db = str(tmp_path / "csak.db")
    return runner.invoke(main, ["--db", db, *args])


def test_org_create_and_list(tmp_path: Path) -> None:
    r = _invoke(["org", "create", "acmecorp"], tmp_path)
    assert r.exit_code == 0, r.output
    assert "Created org acmecorp" in r.output

    r2 = _invoke(["org", "list"], tmp_path)
    assert r2.exit_code == 0
    assert "acmecorp" in r2.output


def test_org_create_duplicate_errors(tmp_path: Path) -> None:
    _invoke(["org", "create", "acme"], tmp_path)
    r = _invoke(["org", "create", "acme"], tmp_path)
    assert r.exit_code != 0
    assert "already exists" in r.output
