import sqlite3

from db.database import init_db
from ingest.nvd_loader import parse_cve, store

# Parser fixture shaped like the NVD API 2.0 response (not live data).
SAMPLE = {
    "cve": {
        "id": "CVE-2021-41773",
        "published": "2021-10-05T09:15:07.593",
        "descriptions": [{"lang": "en", "value": "Path traversal in Apache HTTP Server 2.4.49."}],
        "metrics": {"cvssMetricV31": [{"cvssData": {
            "baseScore": 9.8, "baseSeverity": "CRITICAL", "attackVector": "NETWORK"}}]},
        "configurations": [{"nodes": [{"cpeMatch": [
            {"vulnerable": True, "criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"},
            {"vulnerable": False, "criteria": "cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*"},
        ]}]}],
    }
}


def test_parse_cve_extracts_score_and_products():
    cve_row, products = parse_cve(SAMPLE)
    assert cve_row[0] == "CVE-2021-41773"
    assert cve_row[2] == 9.8 and cve_row[4] == "NETWORK"
    assert products == [("CVE-2021-41773", "apache", "http_server", "2.4.49", None, None, None, None)]


def test_store_roundtrip_and_idempotent():
    conn = sqlite3.connect(":memory:")
    init_db(conn)
    assert store(conn, [SAMPLE]) == 1
    store(conn, [SAMPLE])  # re-run must not duplicate rows
    assert conn.execute("SELECT COUNT(*) FROM cve_products").fetchone()[0] == 1
    assert conn.execute("SELECT cvss_score FROM cves").fetchone()[0] == 9.8
