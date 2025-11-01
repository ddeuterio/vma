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
    id TEXT NOT NULL PRIMARY KEY,
    description TEXT
);

CREATE TABLE images (
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    product TEXT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    PRIMARY KEY (name, version, product)
);

CREATE TABLE image_vulnerabilities (
    image_name TEXT NOT NULL,
    image_version TEXT NOT NULL,
    product TEXT NOT NULL,
    cve TEXT NOT NULL REFERENCES vulnerabilities(cve_id),
    fix_versions TEXT,
    first_seen TIMESTAMPTZ,
    last_seen TIMESTAMPTZ,
    affected_component_type TEXT NOT NULL,
    affected_component TEXT NOT NULL,
    affected_version TEXT NOT NULL,
    affected_path TEXT NOT NULL,
    PRIMARY KEY (image_name, image_version, product, cve, affected_component_type, affected_component),
    FOREIGN KEY (image_name, image_version, product) REFERENCES images(name, version, product) ON DELETE CASCADE
);