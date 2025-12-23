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

CREATE INDEX idx_images_team ON images(team, product);

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
