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
    scanner TEXT NOT NULL,
    vuln_id TEXT NOT NULL,
    source TEXT NOT NULL,

    -- Image linkage
    image_name TEXT NOT NULL,
    image_version TEXT NOT NULL,
    product TEXT NOT NULL,
    team TEXT NOT NULL,

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

    -- Universal format fields for comprehensive vulnerability tracking
    purl TEXT,
    namespace TEXT,
    risk_score REAL,
    cpes JSONB DEFAULT '[]'::jsonb,
    licenses JSONB DEFAULT '[]'::jsonb,
    locations JSONB DEFAULT '[]'::jsonb,
    upstreams JSONB DEFAULT '[]'::jsonb,
    match_details JSONB DEFAULT '[]'::jsonb,

    -- Composite primary key: scanner + vuln + image + artifact
    PRIMARY KEY (scanner, vuln_id, image_name, image_version, product, team, affected_component, affected_version),

    -- Foreign key to images table
    FOREIGN KEY (image_name, image_version, product, team)
        REFERENCES images(name, version, product, team)
        ON DELETE CASCADE
);

-- Performance indexes (base)
CREATE INDEX idx_vuln_sca_team ON vulnerabilities_sca(team);
CREATE INDEX idx_vuln_sca_severity ON vulnerabilities_sca(severity_level);
CREATE INDEX idx_vuln_sca_vuln_id ON vulnerabilities_sca(vuln_id);
CREATE INDEX idx_vuln_sca_image ON vulnerabilities_sca(image_name, image_version);

-- Performance indexes (universal format fields)
CREATE INDEX idx_vuln_sca_purl ON vulnerabilities_sca(purl);
CREATE INDEX idx_vuln_sca_namespace ON vulnerabilities_sca(namespace);
CREATE INDEX idx_vuln_sca_risk ON vulnerabilities_sca(risk_score DESC NULLS LAST);
CREATE INDEX idx_vuln_sca_cpes ON vulnerabilities_sca USING GIN (cpes);
CREATE INDEX idx_vuln_sca_licenses ON vulnerabilities_sca USING GIN (licenses);
CREATE INDEX idx_vuln_sca_image_risk ON vulnerabilities_sca(image_name, image_version, severity_level, risk_score DESC NULLS LAST);

-- Column documentation
COMMENT ON TABLE vulnerabilities_sca IS 'SCA vulnerability findings with universal format support (v2 - 2026-01-30)';
COMMENT ON COLUMN vulnerabilities_sca.purl IS 'Package URL (PURL) - universal package identifier';
COMMENT ON COLUMN vulnerabilities_sca.namespace IS 'Vulnerability source namespace (e.g., nvd:cpe, alpine:distro:alpine:3.19)';
COMMENT ON COLUMN vulnerabilities_sca.risk_score IS 'Scanner-calculated composite risk score';
COMMENT ON COLUMN vulnerabilities_sca.cpes IS 'Array of CPE identifiers for the affected package';
COMMENT ON COLUMN vulnerabilities_sca.licenses IS 'Array of package license identifiers';
COMMENT ON COLUMN vulnerabilities_sca.locations IS 'Array of {path, layer_id} objects showing where package is installed';
COMMENT ON COLUMN vulnerabilities_sca.upstreams IS 'Array of upstream package names';
COMMENT ON COLUMN vulnerabilities_sca.match_details IS 'Array of match detail objects explaining how vulnerability was matched';

-- Standalone SAST vulnerability storage (Semgrep findings)
-- Code-level issues linked to products/teams (no image association)
CREATE TABLE repositories (
    product TEXT NOT NULL,
    team TEXT NOT NULL REFERENCES teams(name) ON DELETE CASCADE,
    name TEXT NOT NULL,
    url TEXT NOT NULL,
    PRIMARY KEY (product, team, name),
    FOREIGN KEY (product, team) REFERENCES products(id, team) ON DELETE CASCADE
);

CREATE INDEX idx_repositories_team ON repositories(team);
CREATE INDEX idx_repositories_product ON repositories(product);


CREATE TABLE vulnerabilities_sast (
    scanner TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    repository TEXT NOT NULL,
    product TEXT NOT NULL,
    team TEXT NOT NULL REFERENCES teams(name) ON DELETE CASCADE,
    file_path TEXT NOT NULL,
    start_line INTEGER NOT NULL,
    start_col INTEGER NOT NULL,
    end_line INTEGER NOT NULL,
    end_col INTEGER NOT NULL,
    message TEXT,
    severity TEXT NOT NULL,
    confidence TEXT,
    code_snippet TEXT,
    suggested_fix TEXT,
    fingerprint TEXT,
    cwes JSONB DEFAULT '[]'::jsonb,
    owasp JSONB DEFAULT '[]'::jsonb,
    refs JSONB DEFAULT '[]'::jsonb,
    category TEXT,
    subcategory JSONB DEFAULT '[]'::jsonb,
    technology JSONB DEFAULT '[]'::jsonb,
    vulnerability_class JSONB DEFAULT '[]'::jsonb,
    impact TEXT,
    likelihood TEXT,
    engine_kind TEXT,
    validation_state TEXT,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (scanner, rule_id, product, team, repository, file_path, start_line, start_col),
    FOREIGN KEY (product, team) REFERENCES products(id, team) ON DELETE CASCADE,
    FOREIGN KEY (repository, product, team)
        REFERENCES repositories(name, product, team)
        ON DELETE CASCADE
);

CREATE INDEX idx_vuln_sast_repo ON vulnerabilities_sast(repository);
CREATE INDEX idx_vuln_sast_team ON vulnerabilities_sast(team);
CREATE INDEX idx_vuln_sast_product ON vulnerabilities_sast(product);
CREATE INDEX idx_vuln_sast_severity ON vulnerabilities_sast(severity);
CREATE INDEX idx_vuln_sast_rule_id ON vulnerabilities_sast(rule_id);
CREATE INDEX idx_vuln_sast_file_path ON vulnerabilities_sast(file_path);
CREATE INDEX idx_vuln_sast_category ON vulnerabilities_sast(category);

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
