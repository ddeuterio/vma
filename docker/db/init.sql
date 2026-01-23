CREATE TABLE teams (
  name TEXT NOT NULL PRIMARY KEY,
  description TEXT
);

CREATE TABLE users (
  email TEXT NOT NULL PRIMARY KEY,
  hpass TEXT NOT NULL CHECK (hpass <> ''),
  name TEXT,
  is_root BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_users_email ON users(email);

CREATE TABLE user_team_scopes (
    user_email TEXT NOT NULL REFERENCES users(email) ON DELETE CASCADE,
    team_id    TEXT NOT NULL REFERENCES teams(name) ON DELETE CASCADE,
    scope      TEXT NOT NULL DEFAULT 'read',-- read|write|admin
    PRIMARY KEY (user_email, team_id)
);

CREATE INDEX idx_user_team_scopes_team ON user_team_scopes(team_id);

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

-- OSV (Open Source Vulnerability) Schema
-- Stores vulnerability data from OSV database (https://osv.dev)
-- Correlation with NVD: osv_aliases.alias = vulnerabilities.cve_id

CREATE TABLE osv_vulnerabilities (
    osv_id TEXT PRIMARY KEY,
    schema_version TEXT NOT NULL,
    modified TIMESTAMPTZ NOT NULL,
    published TIMESTAMPTZ,
    withdrawn TIMESTAMPTZ,
    summary TEXT,
    details TEXT,
    database_specific JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_osv_vuln_modified ON osv_vulnerabilities(modified);
CREATE INDEX idx_osv_vuln_published ON osv_vulnerabilities(published);

CREATE TABLE osv_aliases (
    osv_id TEXT NOT NULL REFERENCES osv_vulnerabilities(osv_id) ON DELETE CASCADE,
    alias TEXT NOT NULL,
    PRIMARY KEY (osv_id, alias)
);

-- Critical index for NVD correlation: JOIN osv_aliases.alias = vulnerabilities.cve_id
CREATE INDEX idx_osv_aliases_alias ON osv_aliases(alias);
CREATE INDEX idx_osv_aliases_cve ON osv_aliases(alias) WHERE alias LIKE 'CVE-%';

CREATE TABLE osv_references (
    id SERIAL PRIMARY KEY,
    osv_id TEXT NOT NULL REFERENCES osv_vulnerabilities(osv_id) ON DELETE CASCADE,
    ref_type TEXT NOT NULL,  -- ADVISORY, ARTICLE, DETECTION, DISCUSSION, REPORT, FIX, etc.
    url TEXT NOT NULL
);

CREATE INDEX idx_osv_refs_osv_id ON osv_references(osv_id);

CREATE TABLE osv_severity (
    id SERIAL PRIMARY KEY,
    osv_id TEXT NOT NULL REFERENCES osv_vulnerabilities(osv_id) ON DELETE CASCADE,
    severity_type TEXT NOT NULL,  -- CVSS_V2, CVSS_V3, CVSS_V4, or custom (e.g., "Ubuntu")
    score TEXT NOT NULL  -- CVSS vector string or numeric score
);

CREATE INDEX idx_osv_severity_osv_id ON osv_severity(osv_id);
CREATE INDEX idx_osv_severity_type ON osv_severity(severity_type);

CREATE TABLE osv_affected (
    id SERIAL PRIMARY KEY,
    osv_id TEXT NOT NULL REFERENCES osv_vulnerabilities(osv_id) ON DELETE CASCADE,
    package_ecosystem TEXT NOT NULL,  -- PyPI, npm, Go, Maven, etc.
    package_name TEXT NOT NULL,
    package_purl TEXT,  -- Package URL (purl) format
    ranges JSONB,  -- Version ranges with events (introduced, fixed, etc.)
    versions JSONB,  -- Explicit array of affected versions
    ecosystem_specific JSONB,
    database_specific JSONB
);

CREATE INDEX idx_osv_affected_osv_id ON osv_affected(osv_id);
CREATE INDEX idx_osv_affected_ecosystem ON osv_affected(package_ecosystem);
CREATE INDEX idx_osv_affected_package ON osv_affected(package_name);
CREATE INDEX idx_osv_affected_eco_pkg ON osv_affected(package_ecosystem, package_name);

CREATE TABLE osv_credits (
    id SERIAL PRIMARY KEY,
    osv_id TEXT NOT NULL REFERENCES osv_vulnerabilities(osv_id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    contact JSONB,  -- Array of contact methods
    credit_type TEXT  -- FINDER, REPORTER, ANALYST, COORDINATOR, etc.
);

CREATE INDEX idx_osv_credits_osv_id ON osv_credits(osv_id);

-- Sync tracking for OSV database updates
CREATE TABLE osv_sync (
    id TEXT PRIMARY KEY,
    last_fetched TIMESTAMPTZ NOT NULL,
    ecosystem TEXT,  -- Track sync per ecosystem (PyPI, npm, etc.) or 'all' for full sync
    records_count INTEGER DEFAULT 0
);

CREATE TABLE products (
    id TEXT NOT NULL,
    description TEXT,
    team TEXT NOT NULL REFERENCES teams(name) ON DELETE CASCADE,
    PRIMARY KEY (id, team)
);

CREATE INDEX idx_products_team ON products(team);

CREATE TABLE images (
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    product TEXT NOT NULL,
    team TEXT NOT NULL REFERENCES teams(name) ON DELETE CASCADE,
    PRIMARY KEY (name, version, product, team),
    FOREIGN KEY (product, team) REFERENCES products(id, team) ON DELETE CASCADE
);

CREATE INDEX idx_images_team_product ON images(team, product);
CREATE INDEX idx_images_product_name_version ON images(product, name, version);
CREATE INDEX idx_images_team ON images(team);

CREATE TABLE image_vulnerabilities (
    scanner TEXT NOT NULL,
    image_name TEXT NOT NULL,
    image_version TEXT NOT NULL,
    product TEXT NOT NULL,
    team TEXT NOT NULL REFERENCES teams(name) ON DELETE CASCADE,
    cve TEXT NOT NULL REFERENCES vulnerabilities(cve_id),
    fix_versions TEXT,
    first_seen TIMESTAMPTZ,
    last_seen TIMESTAMPTZ,
    affected_component_type TEXT NOT NULL,
    affected_component TEXT NOT NULL,
    affected_version TEXT NOT NULL,
    affected_path TEXT NOT NULL,
    PRIMARY KEY (
        scanner,
        image_name,
        image_version,
        product,
        team,
        cve,
        affected_component_type,
        affected_component
    ),
    FOREIGN KEY (image_name, image_version, product, team)
      REFERENCES images(name, version, product, team)
      ON DELETE CASCADE
);

CREATE INDEX idx_image_vuln_team ON image_vulnerabilities(team);

-- Standalone SCA vulnerability storage
-- Maps directly to VulnerabilitySca Pydantic model
-- No dependency on NVD vulnerabilities table
CREATE TABLE vulnerabilities_sca (
    -- Primary identification
    scanner TEXT NOT NULL,
    vuln_id TEXT NOT NULL,
    source TEXT NOT NULL,

    -- Image linkage
    image_name TEXT NOT NULL,
    image_version TEXT NOT NULL,
    product TEXT NOT NULL,
    team TEXT NOT NULL REFERENCES teams(name) ON DELETE CASCADE,

    -- Core vulnerability data
    description TEXT,
    severity_level TEXT,

    -- Artifact/component data
    affected_component_type TEXT NOT NULL,
    affected_component TEXT NOT NULL,
    affected_version TEXT NOT NULL,
    affected_path TEXT NOT NULL,

    -- JSONB for complex nested data
    cvss JSONB DEFAULT '[]'::jsonb,
    epss JSONB DEFAULT '[]'::jsonb,
    urls JSONB DEFAULT '[]'::jsonb,
    cwes JSONB DEFAULT '[]'::jsonb,
    fix JSONB DEFAULT '{}'::jsonb,
    related_vulnerabilities JSONB DEFAULT '[]'::jsonb,

    -- Composite primary key: scanner + vuln + image + artifact
    PRIMARY KEY (scanner, vuln_id, image_name, image_version, product, team, affected_component, affected_version),

    -- Foreign key to images table
    FOREIGN KEY (image_name, image_version, product, team)
        REFERENCES images(name, version, product, team)
        ON DELETE CASCADE
);

-- Performance indexes
CREATE INDEX idx_vuln_sca_team ON vulnerabilities_sca(team);
CREATE INDEX idx_vuln_sca_severity ON vulnerabilities_sca(severity_level);
CREATE INDEX idx_vuln_sca_vuln_id ON vulnerabilities_sca(vuln_id);
CREATE INDEX idx_vuln_sca_image ON vulnerabilities_sca(image_name, image_version);

CREATE TABLE api_tokens (
    id SERIAL PRIMARY KEY,
    token_hash TEXT UNIQUE NOT NULL,
    prefix TEXT NOT NULL,
    user_email TEXT NOT NULL REFERENCES users(email) ON DELETE CASCADE,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    revoked BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX idx_api_token_hash ON api_tokens(token_hash);
CREATE INDEX idx_api_token_prefix ON api_tokens(prefix);
CREATE INDEX idx_api_token_user ON api_tokens(user_email);
CREATE INDEX idx_api_token_revoked ON api_tokens(revoked) WHERE revoked = FALSE;
