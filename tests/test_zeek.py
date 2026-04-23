from pathlib import Path

from csak.ingest.pipeline import ingest_path
from csak.ingest.zeek import parse
from csak.storage import repository as repo


NOTICE_TSV = """\
#separator \\x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	notice
#fields	ts	uid	note	msg	src	dst
#types	time	string	string	string	addr	addr
1744041022.0	abc123	Scan::Port_Scan	Port scan detected	1.2.3.4	10.0.0.10
1744041100.0	def456	Scan::Port_Scan	Port scan detected	1.2.3.4	10.0.0.11
"""


CONN_TSV = """\
#separator \\x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	conn
#fields	ts	uid	id.orig_h	id.resp_h
#types	time	string	addr	addr
1744041000.0	u1	1.2.3.4	10.0.0.10
"""


def _write_log(dir_: Path, name: str, content: str) -> Path:
    p = dir_ / name
    p.write_text(content, encoding="utf-8")
    return p


def test_parse_single_notice_log_extracts_findings(tmp_path: Path) -> None:
    p = _write_log(tmp_path, "notice.log", NOTICE_TSV)
    result = parse(p)
    # Two notice rows become two ProtoFindings.
    assert len(result.findings) == 2
    assert result.scan.timestamp_source == "extracted"


def test_parse_folder_processes_many_logs_as_one_scan(tmp_path: Path) -> None:
    capture = tmp_path / "capture"
    capture.mkdir()
    _write_log(capture, "conn.log", CONN_TSV)
    _write_log(capture, "notice.log", NOTICE_TSV)
    # A non-Zeek file that should be skipped with a warning.
    (capture / "README.txt").write_text("hi", encoding="utf-8")

    result = parse(capture)
    # Only notice rows become findings; conn is surfaced as raw data only.
    assert len(result.findings) == 2
    # Timestamps cover the full window across all logs.
    assert result.scan.scan_started_at.timestamp() == 1744041000.0


def test_pipeline_ingest_of_folder_records_one_scan(
    db, tmp_path: Path, artifacts_dir: Path
) -> None:
    capture = tmp_path / "capture"
    capture.mkdir()
    _write_log(capture, "conn.log", CONN_TSV)
    _write_log(capture, "notice.log", NOTICE_TSV)

    org = repo.create_org(db, name="acme", slug="acme")
    report = ingest_path(
        db,
        org_id=org.id,
        source_tool="zeek",
        path=capture,
        artifacts_root=artifacts_dir,
    )
    # 2 notice findings, dedup key differs by dst so both survive.
    assert report.new_findings == 2
    scans = repo.list_scans(db, org.id)
    assert len(scans) == 1
