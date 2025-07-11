CREATE TABLE vulnerabilities (
    cve_id TEXT PRIMARY KEY,
    source_identifier TEXT,
    published_date TIMESTAMPTZ,
    last_modified TIMESTAMPTZ,
    vuln_status TEXT,
    refs TEXT,
    descriptions JSONB,
    weakness JSONB,
    configurations JSONB

);

CREATE TABLE cvss_metrics (
    cve_id TEXT REFERENCES vulnerabilities(cve_id) ON DELETE CASCADE,
    source TEXT NOT NULL,
    cvss_version TEXT NOT NULL,
    vector_string TEXT NOT NULL,
    base_score FLOAT,
    base_severity TEXT,
    PRIMARY KEY (cve_id, cvss_version, source)
);

CREATE TABLE nvd_sync (
    id TEXT PRIMARY KEY,
    last_fetched TEXT NOT NULL,
    chcksum TEXT NOT NULL
)