from pathlib import Path

from csak.ingest.nessus import parse
from csak.ingest.pipeline import ingest_path
from csak.storage import repository as repo

NESSUS_XML = """<?xml version="1.0" ?>
<NessusClientData_v2>
  <Policy><policyName>Basic Network Scan</policyName></Policy>
  <Report name="April Scan">
    <ReportHost name="10.0.0.10">
      <HostProperties>
        <tag name="host-ip">10.0.0.10</tag>
        <tag name="HOST_START">Tue Apr 21 14:30:22 2026</tag>
        <tag name="HOST_END">Tue Apr 21 14:45:10 2026</tag>
      </HostProperties>
      <ReportItem pluginID="10107" port="80" protocol="tcp" severity="2" pluginName="HTTP Server Banner">
        <description>Remote web server is identified.</description>
        <solution>n/a</solution>
      </ReportItem>
      <ReportItem pluginID="51192" port="443" protocol="tcp" severity="4" pluginName="SSL Certificate expired">
        <description>The certificate has expired.</description>
        <solution>Renew the certificate.</solution>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>
"""


def _write(tmp_path: Path) -> Path:
    p = tmp_path / "scan.nessus"
    p.write_text(NESSUS_XML, encoding="utf-8")
    return p


def test_parse_extracts_timestamps_and_findings(tmp_path: Path) -> None:
    p = _write(tmp_path)
    result = parse(p)
    assert len(result.findings) == 2
    assert result.scan.timestamp_source == "extracted"
    assert result.scan.label.startswith("Basic Network Scan")


def test_ingest_stores_findings_with_correct_severity(
    db, tmp_path: Path, artifacts_dir: Path
) -> None:
    org = repo.create_org(db, name="acme", slug="acme")
    p = _write(tmp_path)
    report = ingest_path(
        db,
        org_id=org.id,
        source_tool="nessus",
        path=p,
        artifacts_root=artifacts_dir,
    )
    assert report.new_findings == 2
    findings = repo.list_findings_for_org(db, org.id)
    severities = sorted(f.severity for f in findings if f.severity)
    assert severities == ["critical", "medium"]
