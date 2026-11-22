"""Load real CVE data from the NVD (API 2.0 format) into SQLite.

Two ways to feed it:
  python -m ingest.nvd_loader --api --pages 3        # pull from the NVD API
  python -m ingest.nvd_loader --file data/raw/x.json # load a saved API 2.0 JSON file
"""
import argparse
import json
import os
import time

from config import NVD_API_KEY, NVD_API_URL
from db.database import get_connection, init_db

CVSS_KEYS = ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2")


def _best_cvss(metrics: dict):
    """Return (score, severity, attack_vector) from the newest CVSS version present."""
    for key in CVSS_KEYS:
        if metrics.get(key):
            m = metrics[key][0]
            data = m.get("cvssData", {})
            severity = data.get("baseSeverity") or m.get("baseSeverity")
            vector = data.get("attackVector") or m.get("accessVector")
            return data.get("baseScore"), severity, vector
    return None, None, None


def _parse_cpe(criteria: str):
    # cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*
    parts = criteria.split(":")
    if len(parts) < 6:
        return None
    vendor, product, version = parts[3], parts[4], parts[5]
    return vendor, product, None if version in ("*", "-") else version


def parse_cve(item: dict):
    """Turn one NVD 2.0 `vulnerabilities[]` entry into (cve_row, product_rows)."""
    cve = item["cve"]
    desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    score, severity, vector = _best_cvss(cve.get("metrics", {}))
    cve_row = (cve["id"], desc, score, severity, vector, cve.get("published"))

    products = []
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable"):
                    continue
                parsed = _parse_cpe(match["criteria"])
                if not parsed:
                    continue
                vendor, product, version = parsed
                products.append((
                    cve["id"], vendor, product, version,
                    match.get("versionStartIncluding"), match.get("versionStartExcluding"),
                    match.get("versionEndIncluding"), match.get("versionEndExcluding"),
                ))
    return cve_row, products


def store(conn, vulnerabilities: list) -> int:
    count = 0
    for item in vulnerabilities:
        cve_row, products = parse_cve(item)
        conn.execute("INSERT OR REPLACE INTO cves VALUES (?,?,?,?,?,?)", cve_row)
        conn.execute("DELETE FROM cve_products WHERE cve_id = ?", (cve_row[0],))
        conn.executemany(
            "INSERT INTO cve_products (cve_id, vendor, product, version, ver_start_incl,"
            " ver_start_excl, ver_end_incl, ver_end_excl) VALUES (?,?,?,?,?,?,?,?)",
            products,
        )
        count += 1
    conn.commit()
    return count


def load_file(conn, path: str) -> int:
    with open(path) as f:
        return store(conn, json.load(f).get("vulnerabilities", []))


def fetch_api(conn, pages: int = 1, per_page: int = 2000) -> int:
    import requests  # imported here so file-based loading works without it

    api_key = NVD_API_KEY or os.environ.get("NVD_API_KEY")
    headers = {"apiKey": api_key} if api_key else {}
    delay = 0.7 if api_key else 6.5  # stay under NVD rate limits
    total = 0
    for page in range(pages):
        params = {"resultsPerPage": per_page, "startIndex": page * per_page}
        resp = requests.get(NVD_API_URL, params=params, headers=headers, timeout=60)
        resp.raise_for_status()
        vulns = resp.json().get("vulnerabilities", [])
        if not vulns:
            break
        total += store(conn, vulns)
        print(f"page {page + 1}: stored {len(vulns)} CVEs")
        time.sleep(delay)
    return total


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--api", action="store_true", help="pull from the NVD API")
    ap.add_argument("--pages", type=int, default=1, help="API pages of 2000 CVEs each")
    ap.add_argument("--file", help="load a saved NVD API 2.0 JSON file")
    args = ap.parse_args()
    if not (args.api or args.file):
        ap.error("pass --api or --file")

    conn = get_connection()
    init_db(conn)
    n = fetch_api(conn, args.pages) if args.api else load_file(conn, args.file)
    print(f"Done: {n} CVEs in database")


if __name__ == "__main__":
    main()
