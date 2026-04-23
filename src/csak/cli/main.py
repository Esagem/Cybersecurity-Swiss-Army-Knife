from __future__ import annotations

import click

from csak import __version__


@click.group()
@click.version_option(__version__, prog_name="csak")
@click.option(
    "--db",
    envvar="CSAK_DB",
    default="csak.db",
    show_default=True,
    help="Path to the CSAK SQLite database.",
)
@click.option(
    "--artifacts-dir",
    envvar="CSAK_ARTIFACTS_DIR",
    default="artifacts",
    show_default=True,
    help="Directory holding raw tool-output bytes (content-addressed).",
)
@click.option(
    "--reports-dir",
    envvar="CSAK_REPORTS_DIR",
    default="reports",
    show_default=True,
    help="Directory for rendered report files.",
)
@click.pass_context
def main(ctx: click.Context, db: str, artifacts_dir: str, reports_dir: str) -> None:
    """CSAK — ingest, triage, and report on security tool output."""
    ctx.ensure_object(dict)
    ctx.obj["db_path"] = db
    ctx.obj["artifacts_dir"] = artifacts_dir
    ctx.obj["reports_dir"] = reports_dir


if __name__ == "__main__":
    main()
