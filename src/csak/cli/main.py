from __future__ import annotations

import click

from csak import __version__
from csak.cli.collect import collect as collect_cmd
from csak.cli.doctor import doctor as doctor_cmd
from csak.cli.findings import findings as findings_group
from csak.cli.ingest import ingest as ingest_cmd
from csak.cli.org import org as org_group
from csak.cli.report import report as report_group
from csak.cli.scan import scan as scan_group
from csak.cli.target import target as target_group


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


main.add_command(org_group)
main.add_command(ingest_cmd)
main.add_command(collect_cmd)
main.add_command(doctor_cmd)
main.add_command(findings_group)
main.add_command(target_group)
main.add_command(scan_group)
main.add_command(report_group)


if __name__ == "__main__":
    main()
