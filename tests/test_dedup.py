from csak.ingest import dedup


def test_nuclei_key_uses_template_and_matched_at() -> None:
    k = dedup.key_for(
        "nuclei",
        {"template-id": "ssl-dns-names", "matched-at": "https://acme.com"},
    )
    assert k == "ssl-dns-names|https://acme.com"


def test_nessus_key_combines_plugin_host_port() -> None:
    k = dedup.key_for(
        "nessus", {"plugin_id": "10107", "host": "10.0.0.1", "port": "443"}
    )
    assert k == "10107|10.0.0.1|443"


def test_zeek_notice_uses_note_src_dst() -> None:
    k = dedup.key_for(
        "zeek",
        {"log_type": "notice", "note": "Scan::Port_Scan", "src": "1.1.1.1", "dst": "2.2.2.2"},
    )
    assert k == "notice|Scan::Port_Scan|1.1.1.1|2.2.2.2"


def test_subfinder_key_is_the_subdomain() -> None:
    k = dedup.key_for("subfinder", {"host": "api.acme.com"})
    assert k == "api.acme.com"


def test_httpx_key_is_the_url() -> None:
    k = dedup.key_for("httpx", {"url": "https://api.acme.com/health"})
    assert k == "https://api.acme.com/health"


def test_osquery_key_combines_name_and_row_hash() -> None:
    k1 = dedup.key_for(
        "osquery",
        {"query_name": "users", "row": {"uid": "0", "username": "root"}},
    )
    k2 = dedup.key_for(
        "osquery",
        {"query_name": "users", "row": {"username": "root", "uid": "0"}},
    )
    # Hashing is key-order-stable.
    assert k1 == k2
