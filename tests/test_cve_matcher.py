import sqlite3

from db.database import init_db
from ingest.cve_matcher import match_service, normalize, version_key
from ingest.nvd_loader import store


def _vuln(cve_id, score, vendor, product, **match):
    # Fixture shaped like the NVD API 2.0 response (not live data).
    cpe = f"cpe:2.3:a:{vendor}:{product}:{match.pop('exact', '*')}:*:*:*:*:*:*:*"
    return {"cve": {
        "id": cve_id, "published": "2021-01-01T00:00:00", "descriptions": [{"lang": "en", "value": "x"}],
        "metrics": {"cvssMetricV31": [{"cvssData": {
            "baseScore": score, "baseSeverity": "HIGH", "attackVector": "NETWORK"}}]},
        "configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": cpe, **match}]}]}],
    }}


def make_db():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    init_db(conn)
    store(conn, [
        _vuln("CVE-A-exact", 9.8, "apache", "http_server", exact="2.4.49"),
        _vuln("CVE-B-range", 7.5, "apache", "http_server",
              versionStartIncluding="2.4.0", versionEndExcluding="2.4.52"),
        _vuln("CVE-C-old", 8.0, "apache", "http_server", exact="2.2.34"),
        _vuln("CVE-D-other", 9.0, "openbsd", "openssh", exact="7.2"),
    ])
    return conn


def test_normalize():
    assert normalize("Apache httpd") == [("apache", "http_server")]
    assert normalize("Samba smbd") == [("samba", "samba")]   # substring fallback
    assert normalize("totally unknown") == []


def test_version_compare_is_numeric():
    assert version_key("2.4.9") < version_key("2.4.10")


def test_matches_exact_and_range_only():
    ids = [m["cve_id"] for m in match_service(make_db(), "Apache httpd", "2.4.49")]
    assert ids == ["CVE-A-exact", "CVE-B-range"]          # sorted by score; 2.2.34 and OpenSSH excluded


def test_range_end_is_exclusive():
    ids = [m["cve_id"] for m in match_service(make_db(), "Apache httpd", "2.4.52")]
    assert "CVE-B-range" not in ids


def test_no_version_gives_possible():
    result = match_service(make_db(), "Apache httpd")
    assert len(result) == 3 and {m["confidence"] for m in result} == {"possible"}


def test_unknown_service_returns_empty():
    assert match_service(make_db(), "mystery daemon", "1.0") == []
