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
);

CREATE TABLE products (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT
);

CREATE TABLE images (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    product TEXT REFERENCES products(name) ON DELETE CASCADE
);

CREATE TABLE image_vulnerabilities (
    image_name TEXT NOT NULL REFERENCES images(name) ON DELETE CASCADE,
    image_version TEXT NOT NULL REFERENCES images(version) ON DELETE CASCADE,
    cve TEXT NOT NULL REFERENCES vulnerabilities(cve_id) ON DELETE CASCADE,
    fix_versions TEXT,
    first_seen TIMESTAMPTZ,
    last_seen TIMESTAMPTZ,
    affected_component_type TEXT NOT NULL,
    affected_component TEXT NOT NULL,
    affected_version TEXT NOT NULL,
    affected_path TEXT NOT NULL,
    PRIMARY KEY (image_name, image_version, cve)
);