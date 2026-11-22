CREATE TABLE IF NOT EXISTS cves (
    cve_id        TEXT PRIMARY KEY,
    description   TEXT,
    cvss_score    REAL,
    severity      TEXT,
    attack_vector TEXT,
    published     TEXT
);

CREATE TABLE IF NOT EXISTS cve_products (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id        TEXT NOT NULL REFERENCES cves(cve_id) ON DELETE CASCADE,
    vendor        TEXT NOT NULL,
    product       TEXT NOT NULL,
    version       TEXT,
    ver_start_incl TEXT,
    ver_start_excl TEXT,
    ver_end_incl   TEXT,
    ver_end_excl   TEXT
);

CREATE INDEX IF NOT EXISTS idx_products_lookup ON cve_products(product, vendor);
CREATE INDEX IF NOT EXISTS idx_cves_score ON cves(cvss_score);
