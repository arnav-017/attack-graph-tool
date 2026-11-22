"""Match a discovered service (name + version) to CVEs in the local database.

Steps: normalize name -> look up candidates -> check version -> rank.
"""
import re
from itertools import zip_longest

# Scanner product name (lowercase) -> list of (vendor, product) as NVD spells them.
# Extend this whenever a real scan produces a name that doesn't match.
ALIASES = {
    "apache httpd": [("apache", "http_server")],
    "apache tomcat": [("apache", "tomcat")],
    "openssh": [("openbsd", "openssh")],
    "nginx": [("nginx", "nginx")],
    "lighttpd": [("lighttpd", "lighttpd")],
    "microsoft iis": [("microsoft", "internet_information_services")],
    "mysql": [("oracle", "mysql"), ("mysql", "mysql")],
    "postgresql": [("postgresql", "postgresql")],
    "vsftpd": [("beasts", "vsftpd")],
    "proftpd": [("proftpd", "proftpd")],
    "samba": [("samba", "samba")],
    "postfix": [("postfix", "postfix")],
    "exim": [("exim", "exim")],
    "dovecot": [("dovecot", "dovecot")],
    "isc bind": [("isc", "bind")],
    "openssl": [("openssl", "openssl")],
}


def normalize(service_name: str):
    """Return the (vendor, product) candidates for a scanner service name."""
    name = service_name.strip().lower()
    if name in ALIASES:
        return ALIASES[name]
    # Fallback: scanner strings often carry extras, e.g. "Samba smbd", "Microsoft IIS httpd".
    for key in sorted(ALIASES, key=len, reverse=True):
        if key in name:
            return ALIASES[key]
    return []


def version_key(v: str) -> tuple:
    """'2.4.10' -> (2, 4, 10). Compared numerically, so 2.4.9 < 2.4.10.
    Letter suffixes are folded in as extra numbers ('7.2p2' -> (7, 2, 2))."""
    return tuple(int(n) for n in re.findall(r"\d+", v))


def _cmp(a: str, b: str) -> int:
    for x, y in zip_longest(version_key(a), version_key(b), fillvalue=0):
        if x != y:
            return -1 if x < y else 1
    return 0


def _row_affects(row, version: str) -> bool:
    """Does this cve_products row cover `version`?"""
    if row["version"]:                       # exact version listed
        return _cmp(version, row["version"]) == 0
    has_range = any(row[k] for k in ("ver_start_incl", "ver_start_excl",
                                     "ver_end_incl", "ver_end_excl"))
    if not has_range:                        # no version info: all versions affected
        return True
    if row["ver_start_incl"] and _cmp(version, row["ver_start_incl"]) < 0:
        return False
    if row["ver_start_excl"] and _cmp(version, row["ver_start_excl"]) <= 0:
        return False
    if row["ver_end_incl"] and _cmp(version, row["ver_end_incl"]) > 0:
        return False
    if row["ver_end_excl"] and _cmp(version, row["ver_end_excl"]) >= 0:
        return False
    return True


def match_service(conn, service_name: str, version: str | None = None) -> list[dict]:
    """Return CVEs affecting this service, highest CVSS first.

    confidence = "confirmed" when the version was checked against the CVE's
    affected versions, "possible" when the scan gave no version.
    """
    found = {}
    for vendor, product in normalize(service_name):
        rows = conn.execute(
            """SELECT p.*, c.description, c.cvss_score, c.severity, c.attack_vector
               FROM cve_products p JOIN cves c ON c.cve_id = p.cve_id
               WHERE p.vendor = ? AND p.product = ?""",
            (vendor, product),
        ).fetchall()
        for row in rows:
            if version and not _row_affects(row, version):
                continue
            found[row["cve_id"]] = {
                "cve_id": row["cve_id"],
                "cvss_score": row["cvss_score"],
                "severity": row["severity"],
                "attack_vector": row["attack_vector"],
                "description": row["description"],
                "confidence": "confirmed" if version else "possible",
            }
    return sorted(found.values(), key=lambda m: m["cvss_score"] or 0, reverse=True)
