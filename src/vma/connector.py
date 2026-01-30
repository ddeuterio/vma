import os
import json
from typing import Optional

from loguru import logger
from dotenv import load_dotenv
from datetime import datetime

import asyncpg
from asyncpg import Pool

load_dotenv()

_db_host = os.getenv("DB_HOST")
_db_user = os.getenv("DB_USER")
_db_pass = os.getenv("DB_PASS")
_db_name = os.getenv("DB_NAME")
_min_conn = int(os.getenv("MIN_CONN") or 2)
_max_conn = int(os.getenv("MAX_CONN") or 20)
_page_size = int(os.getenv("PAGE_SIZE") or 1000)

queries = {
    "get_fetch_date": """
        SELECT
            last_fetched
        FROM
            nvd_sync
        WHERE
            id = $1;
    """,
    "get_nvd_sync_data": """
        SELECT
            id, last_fetched, chcksum
        FROM
            nvd_sync
        WHERE
            id = $1;
    """,
    "get_all_years_nvd_sync": """
        SELECT
            id
        FROM
            nvd_sync
        WHERE
            id != 'recent';
    """,
    "get_cves": """
        SELECT
            v.cve_id,
            v.source_identifier,
            v.published_date,
            v.last_modified,
            v.vuln_status,
            v.refs,
            v.descriptions,
            v.weakness,
            v.configurations,
            COALESCE(
                json_agg(
                    json_build_object(
                        'source', cm.source,
                        'cvss_version', cm.cvss_version,
                        'vector_string', cm.vector_string,
                        'base_score', cm.base_score,
                        'base_severity', cm.base_severity
                    ) ORDER BY cm.base_score DESC
                ) FILTER (WHERE cm.source IS NOT NULL),
                '[]'::json
            ) as cvss_metrics
        FROM
            vulnerabilities v
        LEFT JOIN
            cvss_metrics cm
        ON
            v.cve_id = cm.cve_id
        WHERE
            v.cve_id ILIKE $1
        GROUP BY
            v.cve_id,
            v.source_identifier,
            v.published_date,
            v.last_modified,
            v.vuln_status,
            v.refs,
            v.descriptions,
            v.weakness,
            v.configurations
        ORDER BY
            v.cve_id DESC
        LIMIT 25;
    """,
    "insert_cve": """
        INSERT INTO vulnerabilities
            (cve_id, source_identifier, published_date, last_modified, vuln_status, refs, descriptions, weakness, configurations)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        ON CONFLICT (cve_id)
        DO UPDATE SET
            cve_id = EXCLUDED.cve_id,
            source_identifier = EXCLUDED.source_identifier,
            published_date = EXCLUDED.published_date,
            last_modified = EXCLUDED.last_modified,
            vuln_status = EXCLUDED.vuln_status,
            refs = EXCLUDED.refs,
            descriptions = EXCLUDED.descriptions, 
            weakness = EXCLUDED.weakness,
            configurations = EXCLUDED.configurations;
    """,
    "insert_cvss": """
        INSERT INTO cvss_metrics
            (cve_id, source, cvss_version, vector_string, base_score, base_severity)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (cve_id, source, cvss_version)
        DO UPDATE SET
            vector_string = EXCLUDED.vector_string,
            base_score = EXCLUDED.base_score,
            base_severity = EXCLUDED.base_severity;
    """,
    "insert_fetch_date": """
        INSERT INTO nvd_sync
            (id, last_fetched, chcksum)
        VALUES ($1, $2, $3)
        ON CONFLICT (id)
        DO UPDATE SET
            last_fetched = EXCLUDED.last_fetched,
            chcksum = EXCLUDED.chcksum;    
    """,
    "get_products": """
        SELECT
            id, description, team
        FROM
            products
        WHERE
            team = ANY($1)
        ORDER BY
            id;
    """,
    "get_product": """
        SELECT
            id, description, team
        FROM
            products
        WHERE
            id = $1 AND
            team = ANY($2)
        ORDER BY
            id;
    """,
    "insert_product": """
        INSERT INTO
            products (id, description, team)
        VALUES
            ($1, $2, $3)
        RETURNING
            id;
    """,
    "delete_product": """
        DELETE FROM
            products
        WHERE
            id = $1 AND
            team = $2;
    """,
    "get_images": """
        SELECT
            name,
            version,
            product,
            team
        FROM
            images
        WHERE
            team = ANY($1)
        ORDER BY
            team,
            product,
            name,
            version;
    """,
    "get_images_by_name": """
        SELECT
            name,
            version,
            product,
            team
        FROM
            images
        WHERE
            name = $1 AND
            team = ANY($2)
        ORDER BY
            product,
            name,
            version;
    """,
    "get_images_by_product": """
        SELECT
            name,
            version,
            product,
            team
        FROM
            images
        WHERE
            product = $1 AND
            team = ANY($2)
        ORDER BY
            product,
            name,
            version;
    """,
    "get_images_by_name_product": """
        SELECT
            name,
            version,
            product,
            team
        FROM
            images
        WHERE
            name = $1 AND
            product = $2 AND
            team = ANY($3)
        ORDER BY
            product,
            name,
            version;
    """,
    "get_images_by_name_version_product": """
        SELECT
            name,
            version,
            product,
            team
        FROM
            images
        WHERE
            name = $1 AND
            version = $2 AND
            product = $3 AND
            team = ANY($4)
        ORDER BY
            product,
            name,
            version;
    """,
    "insert_image": """
        INSERT INTO
            images (name, version, product, team)
        VALUES
            ($1, $2, $3, $4)
        RETURNING
            name, version, product, team;
    """,
    "delete_image_by_name": """
        DELETE FROM
            images
        WHERE
            name = $1 AND
            product = $2 AND
            team = $3;
    """,
    "delete_image_by_name_version": """
        DELETE FROM
            images
        WHERE
            name = $1 AND
            version = $2 AND
            product = $3 AND
            team = $4;
    """,
    "get_image_vulnerabilities": """
        SELECT
            iv.cve,
            iv.fix_versions,
            iv.affected_component_type,
            iv.affected_component,
            iv.affected_version,
            iv.affected_path,
            iv.first_seen,
            iv.last_seen,
            cv.base_score,
            cv.base_severity,
            cv.cvss_version
        FROM
            image_vulnerabilities iv
        LEFT JOIN (
            SELECT cve_id,
                   source,
                   cvss_version,
                   base_score,
                   base_severity
            FROM (
                SELECT *,
                       ROW_NUMBER() OVER (
                           PARTITION BY cve_id
                           ORDER BY base_score DESC NULLS LAST
                       ) AS rn
                FROM cvss_metrics
            ) ranked
            WHERE rn = 1
        ) cv ON cv.cve_id = iv.cve
        WHERE
            iv.product = $1
            AND iv.image_name = $2
            AND iv.image_version = $3
            AND iv.team = $4
        ORDER BY
            iv.cve,
            iv.affected_component;
    """,
    "insert_image_vulnerabilities": """
        INSERT INTO image_vulnerabilities
            (scanner, image_name, image_version, product, team, cve, fix_versions, affected_component_type, affected_component, affected_version, affected_path)
        VALUES
            $1
        ON CONFLICT
            (scanner, image_name, image_version, product, team, cve, affected_component_type, affected_component)
        DO UPDATE SET
            last_seen = EXCLUDED.last_seen;
    """,
    "compare_image_versions": """
        WITH image_a AS (
            SELECT DISTINCT
                scanner,
                source,
                vuln_id,
                affected_component_type,
                affected_component,
                affected_path
            FROM vulnerabilities_sca
            WHERE team = $1
            AND product = $2
            AND image_name = $3
            AND image_version = $4
        ),
        image_b AS (
            SELECT DISTINCT
                scanner,
                source,
                vuln_id,
                affected_component_type,
                affected_component,
                affected_path
            FROM vulnerabilities_sca
            WHERE team = $1
            AND product = $2
            AND image_name = $3
            AND image_version = $5
        ),
        diff AS (
            SELECT
                COALESCE(a.vuln_id, b.vuln_id) AS vuln_id,
                COALESCE(a.scanner, b.scanner) AS scanner,
                COALESCE(a.source, b.source) AS source,
                COALESCE(a.affected_component_type, b.affected_component_type) AS affected_component_type,
                COALESCE(a.affected_component, b.affected_component) AS affected_component,
                COALESCE(a.affected_path, b.affected_path) AS affected_path,
                CASE
                    WHEN a.vuln_id IS NOT NULL AND b.vuln_id IS NOT NULL THEN 'shared'
                    WHEN a.vuln_id IS NOT NULL THEN 'only_version_a'
                    ELSE 'only_version_b'
                END AS comparison,
                CASE
                    WHEN a.vuln_id IS NOT NULL THEN $4
                    ELSE $5
                END AS source_version
            FROM image_a a
            FULL OUTER JOIN image_b b USING (vuln_id, scanner, source, affected_component_type, affected_component)
        )
        SELECT
            d.vuln_id,
            v.severity_level,
            d.comparison,
            d.affected_component_type,
            d.affected_component,
            d.affected_path,
            v.cvss,
            v.epss,
            v.urls,
            v.cwes,
            v.fix
        FROM diff d
        JOIN vulnerabilities_sca v ON
            v.vuln_id = d.vuln_id
            AND v.scanner = d.scanner
            AND v.source = d.source
            AND v.affected_component_type = d.affected_component_type
            AND v.affected_component = d.affected_component
            AND v.team = $1
            AND v.product = $2
            AND v.image_name = $3
            AND v.image_version = d.source_version
        ORDER BY v.severity_level DESC, d.vuln_id;
    """,
    "get_users": """
        SELECT
            email, hpass, name, is_root
        FROM
            users;
    """,
    "get_users_by_email": """
        SELECT
            email, hpass, name, is_root
        FROM
            users
        WHERE
            email = $1;
    """,
    "get_users_by_password": """
        SELECT
            email, hpass, name, is_root
        FROM
            users
        WHERE
            email = $1 AND
            hpass = $2;
    """,
    "get_users_by_team": """
        SELECT
            email, hpass, name, is_root
        FROM
            users
        WHERE
            team = $1;
    """,
    "insert_users": """
        INSERT INTO
            users (email, hpass, name, is_root)
        VALUES
            ($1, $2, $3, $4)
        RETURNING email;
    """,
    "delete_user_by_email": """
        DELETE FROM
            users
        WHERE
            email = $1;
    """,
    "get_teams": """
        SELECT
            name, description
        FROM
            teams;
    """,
    "get_teams_by_name": """
        SELECT
            name, description
        FROM
            teams
        WHERE
            name = $1;
    """,
    "insert_teams": """
        INSERT INTO
            teams (name, description)
        VALUES
            ($1, $2)
        RETURNING
            name;
    """,
    "delete_teams": """
        DELETE FROM
            teams
        WHERE
            name = $1;
    """,
    "get_user_team_scopes": """
        SELECT
            user_email, team_id, scope
        FROM
            user_team_scopes;
    """,
    "get_user_team_scopes_by_email": """
        SELECT
            user_email, team_id, scope
        FROM
            user_team_scopes
        WHERE
            user_email = $1;
    """,
    "insert_user_team_scopes": """
        INSERT INTO user_team_scopes 
            (user_email, team_id, scope)
        VALUES
            ($1, $2, $3)
        ON CONFLICT
            (user_email, team_id)
        DO UPDATE SET
            scope = EXCLUDED.scope;
    """,
    "update_user_team_scopes": """
        UPDATE
            user_team_scopes
        SET
            user_email = $1,
            team_id = $2,
            scope = $3
        WHERE
            user_email = $4;
    """,
    "delete_user_team_scopes_by_user": """
        DELETE FROM
            user_team_scopes
        WHERE
            user_email = $1;
    """,
    "insert_api_token": """
        INSERT INTO
            api_tokens (token_hash, prefix, user_email, description, expires_at)
        VALUES
            ($1, $2, $3, $4, $5)
        RETURNING
            id, prefix, created_at;
    """,
    "get_api_token_by_hash": """
        SELECT
            id, token_hash, user_email, revoked, expires_at, last_used_at, description
        FROM
            api_tokens
        WHERE
            token_hash = $1;
    """,
    "get_api_token_by_prefix": """
        SELECT
            id, token_hash, user_email, revoked, expires_at, last_used_at, description
        FROM
            api_tokens
        WHERE
            prefix = $1;
    """,
    "list_api_tokens_by_user": """
        SELECT
            id, prefix, user_email, description, created_at, last_used_at, expires_at, revoked
        FROM
            api_tokens
        WHERE
            user_email = $1 AND
            revoked = FALSE
        ORDER BY
            created_at DESC;
    """,
    "list_all_api_tokens": """
        SELECT
            id, prefix, user_email, description, created_at, last_used_at, expires_at, revoked
        FROM
            api_tokens
        WHERE
            revoked = FALSE
        ORDER BY
            created_at DESC;
    """,
    "revoke_api_token": """
        UPDATE
            api_tokens
        SET
            revoked = TRUE
        WHERE
            id = $1 AND
            user_email = $2
        RETURNING id;
    """,
    "revoke_api_token_admin": """
        UPDATE
            api_tokens
        SET
            revoked = TRUE
        WHERE
            id = $1
        RETURNING id;
    """,
    "update_token_last_used": """
        UPDATE
            api_tokens
        SET
            last_used_at = NOW()
        WHERE
            id = $1;
    """,
    "update_user_password": """
        UPDATE users
        SET hpass = $1
        WHERE email = $2;
    """,
    "update_user_name": """
        UPDATE users
        SET name = $1
        WHERE email = $2;
    """,
    "update_user_root": """
        UPDATE users
        SET is_root = $1
        WHERE email = $2;
    """,
    "update_user_password_name": """
        UPDATE users
        SET hpass = $1, name = $2
        WHERE email = $3;
    """,
    "get_api_token_by_id": """
        SELECT
            id, prefix, user_email, description, created_at, last_used_at, expires_at, revoked
        FROM
            api_tokens
        WHERE
            id = $1;
    """,
    "insert_osv_vulnerability": """
        INSERT INTO osv_vulnerabilities
            (osv_id, schema_version, modified, published, withdrawn, summary, details, database_specific)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        ON CONFLICT (osv_id)
        DO UPDATE SET
            schema_version = EXCLUDED.schema_version,
            modified = EXCLUDED.modified,
            published = EXCLUDED.published,
            withdrawn = EXCLUDED.withdrawn,
            summary = EXCLUDED.summary,
            details = EXCLUDED.details,
            database_specific = EXCLUDED.database_specific;
    """,
    "insert_osv_alias": """
        INSERT INTO osv_aliases
            (osv_id, alias)
        VALUES ($1, $2)
        ON CONFLICT (osv_id, alias)
        DO NOTHING;
    """,
    "insert_osv_reference": """
        INSERT INTO osv_references
            (osv_id, ref_type, url)
        VALUES ($1, $2, $3);
    """,
    "insert_osv_severity": """
        INSERT INTO osv_severity
            (osv_id, severity_type, score)
        VALUES ($1, $2, $3);
    """,
    "insert_osv_affected": """
        INSERT INTO osv_affected
            (osv_id, package_ecosystem, package_name, package_purl, ranges, versions, ecosystem_specific, database_specific)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8);
    """,
    "insert_osv_credit": """
        INSERT INTO osv_credits
            (osv_id, name, contact, credit_type)
        VALUES ($1, $2, $3, $4);
    """,
    "delete_osv_references": """
        DELETE FROM osv_references WHERE osv_id = $1;
    """,
    "delete_osv_severity": """
        DELETE FROM osv_severity WHERE osv_id = $1;
    """,
    "delete_osv_affected": """
        DELETE FROM osv_affected WHERE osv_id = $1;
    """,
    "delete_osv_credits": """
        DELETE FROM osv_credits WHERE osv_id = $1;
    """,
    "get_osv_by_id": """
        SELECT
            osv_id, schema_version, modified, published, withdrawn, summary, details, database_specific
        FROM
            osv_vulnerabilities
        WHERE
            osv_id = $1;
    """,
    "get_osvs": """
        SELECT
            v.osv_id,
            v.schema_version,
            v.modified,
            v.published,
            v.withdrawn,
            v.summary,
            v.details,
            v.database_specific,
            COALESCE(
                json_agg(
                    json_build_object(
                        'type', s.severity_type,
                        'score', s.score
                    )
                ) FILTER (WHERE s.severity_type IS NOT NULL),
                '[]'::json
            ) as severity
        FROM
            osv_vulnerabilities v
        LEFT JOIN
            osv_severity s ON v.osv_id = s.osv_id
        WHERE
            v.osv_id ILIKE $1
        GROUP BY
            v.osv_id,
            v.schema_version,
            v.modified,
            v.published,
            v.withdrawn,
            v.summary,
            v.details,
            v.database_specific
        ORDER BY
            v.osv_id DESC
        LIMIT 25;
    """,
    "get_osv_aliases": """
        SELECT
            alias
        FROM
            osv_aliases
        WHERE
            osv_id = $1;
    """,
    "get_osv_by_cve": """
        SELECT
            v.osv_id, v.schema_version, v.modified, v.published, v.withdrawn, v.summary, v.details
        FROM
            osv_vulnerabilities v
        INNER JOIN
            osv_aliases a ON v.osv_id = a.osv_id
        WHERE
            a.alias = $1;
    """,
    "correlate_nvd_osv": """
        SELECT
            nv.cve_id,
            nv.published_date as nvd_published,
            nv.last_modified as nvd_modified,
            ov.osv_id,
            ov.published as osv_published,
            ov.modified as osv_modified,
            ov.summary,
            ov.details
        FROM
            vulnerabilities nv
        INNER JOIN
            osv_aliases oa ON nv.cve_id = oa.alias
        INNER JOIN
            osv_vulnerabilities ov ON oa.osv_id = ov.osv_id
        WHERE
            nv.cve_id = $1;
    """,
    "insert_vulnerability_sca": """
        INSERT INTO vulnerabilities_sca
            (scanner, vuln_id, source, image_name, image_version, product, team,
             description, severity_level,
             affected_component_type, affected_component, affected_version, affected_path,
             cvss, epss, urls, cwes, fix, related_vulnerabilities,
             purl, namespace, risk_score, cpes, licenses, locations, upstreams, match_details)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19,
                $20, $21, $22, $23, $24, $25, $26, $27)
        ON CONFLICT (scanner, vuln_id, image_name, image_version, product, team, affected_component, affected_version)
        DO UPDATE SET
            source = EXCLUDED.source,
            description = EXCLUDED.description,
            severity_level = EXCLUDED.severity_level,
            affected_component_type = EXCLUDED.affected_component_type,
            affected_path = EXCLUDED.affected_path,
            cvss = EXCLUDED.cvss,
            epss = EXCLUDED.epss,
            urls = EXCLUDED.urls,
            cwes = EXCLUDED.cwes,
            fix = EXCLUDED.fix,
            related_vulnerabilities = EXCLUDED.related_vulnerabilities,
            purl = EXCLUDED.purl,
            namespace = EXCLUDED.namespace,
            risk_score = EXCLUDED.risk_score,
            cpes = EXCLUDED.cpes,
            licenses = EXCLUDED.licenses,
            locations = EXCLUDED.locations,
            upstreams = EXCLUDED.upstreams,
            match_details = EXCLUDED.match_details;
    """,
    "get_vulnerabilities_sca_by_image": """
        SELECT scanner, vuln_id, source, description, severity_level,
               affected_component_type, affected_component, affected_version, affected_path,
               cvss, epss, urls, cwes, fix, related_vulnerabilities,
               purl, namespace, risk_score, cpes, licenses, locations, upstreams, match_details
        FROM vulnerabilities_sca
        WHERE image_name = $1
          AND image_version = $2
          AND product = $3
          AND team = $4
        ORDER BY
            CASE severity_level
                WHEN 'Critical' THEN 1
                WHEN 'High' THEN 2
                WHEN 'Medium' THEN 3
                WHEN 'Low' THEN 4
                WHEN 'Negligible' THEN 5
                ELSE 6
            END,
            risk_score DESC NULLS LAST,
            vuln_id;
    """,
    "get_vulnerability_sca_by_id": """
        SELECT scanner, vuln_id, source, image_name, image_version, product, team,
               description, severity_level,
               affected_component_type, affected_component, affected_version, affected_path,
               cvss, epss, urls, cwes, fix, related_vulnerabilities,
               purl, namespace, risk_score, cpes, licenses, locations, upstreams, match_details
        FROM vulnerabilities_sca
        WHERE vuln_id = $1 AND team = $2;
    """,
    "insert_vulnerability_sast": """
        INSERT INTO vulnerabilities_sast
            (scanner, rule_id, product, team, file_path,
             start_line, start_col, end_line, end_col,
             message, severity, confidence, code_snippet, suggested_fix, fingerprint,
             cwes, owasp, refs, category, subcategory, technology,
             vulnerability_class, impact, likelihood, engine_kind, validation_state)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15,
                $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26)
        ON CONFLICT (scanner, rule_id, product, team, file_path, start_line, start_col)
        DO UPDATE SET
            end_line = EXCLUDED.end_line,
            end_col = EXCLUDED.end_col,
            message = EXCLUDED.message,
            severity = EXCLUDED.severity,
            confidence = EXCLUDED.confidence,
            code_snippet = EXCLUDED.code_snippet,
            suggested_fix = EXCLUDED.suggested_fix,
            fingerprint = EXCLUDED.fingerprint,
            cwes = EXCLUDED.cwes,
            owasp = EXCLUDED.owasp,
            refs = EXCLUDED.refs,
            category = EXCLUDED.category,
            subcategory = EXCLUDED.subcategory,
            technology = EXCLUDED.technology,
            vulnerability_class = EXCLUDED.vulnerability_class,
            impact = EXCLUDED.impact,
            likelihood = EXCLUDED.likelihood,
            engine_kind = EXCLUDED.engine_kind,
            validation_state = EXCLUDED.validation_state,
            last_seen = now();
    """,
    "get_vulnerabilities_sast_by_product": """
        SELECT scanner, rule_id, product, team, file_path,
               start_line, start_col, end_line, end_col,
               message, severity, confidence, code_snippet, suggested_fix, fingerprint,
               cwes, owasp, refs, category, subcategory, technology,
               vulnerability_class, impact, likelihood, engine_kind, validation_state,
               first_seen, last_seen
        FROM vulnerabilities_sast
        WHERE product = $1 AND team = $2
        ORDER BY
            CASE severity
                WHEN 'ERROR' THEN 1
                WHEN 'WARNING' THEN 2
                WHEN 'INFO' THEN 3
                ELSE 4
            END,
            rule_id;
    """,
    "get_vulnerabilities_sast_by_team": """
        SELECT scanner, rule_id, product, team, file_path,
               start_line, start_col, end_line, end_col,
               message, severity, confidence, code_snippet, suggested_fix, fingerprint,
               cwes, owasp, refs, category, subcategory, technology,
               vulnerability_class, impact, likelihood, engine_kind, validation_state,
               first_seen, last_seen
        FROM vulnerabilities_sast
        WHERE team = $1
        ORDER BY
            CASE severity
                WHEN 'ERROR' THEN 1
                WHEN 'WARNING' THEN 2
                WHEN 'INFO' THEN 3
                ELSE 4
            END,
            product, rule_id;
    """,
    "get_vulnerability_sast_by_rule": """
        SELECT scanner, rule_id, product, team, file_path,
               start_line, start_col, end_line, end_col,
               message, severity, confidence, code_snippet, suggested_fix, fingerprint,
               cwes, owasp, refs, category, subcategory, technology,
               vulnerability_class, impact, likelihood, engine_kind, validation_state,
               first_seen, last_seen
        FROM vulnerabilities_sast
        WHERE rule_id = $1 AND team = $2
        ORDER BY product, file_path, start_line;
    """,
    "delete_vulnerabilities_sast_by_product": """
        DELETE FROM vulnerabilities_sast
        WHERE product = $1 AND team = $2;
    """,
    "get_sast_stats_by_team": """
        SELECT
            product,
            COUNT(*) AS total,
            COUNT(*) FILTER (WHERE severity = 'ERROR') AS errors,
            COUNT(*) FILTER (WHERE severity = 'WARNING') AS warnings,
            COUNT(*) FILTER (WHERE severity = 'INFO') AS info
        FROM vulnerabilities_sast
        WHERE team = $1
        GROUP BY product
        ORDER BY product;
    """,
}

_conn_pool = None


async def create_pool() -> Pool:
    return await asyncpg.create_pool(
        host=_db_host,
        database=_db_name,
        user=_db_user,
        password=_db_pass,
        min_size=_min_conn,
        max_size=_max_conn,
    )


async def get_pool():
    global _conn_pool
    if _conn_pool is None:
        _conn_pool = await create_pool()
    return _conn_pool


async def close_pool():
    global _conn_pool
    if _conn_pool is not None:
        await _conn_pool.close()
        _conn_pool = None


async def get_all_years_nvd_sync() -> list:
    """
    Gets the date (extended ISO-8601 date/time format) of the last time that the database was updated for all years.

    Returns:
        Date of the last time that the vulnerabilities where updated
    """
    dt = None
    pool = await get_pool()
    try:
        async with pool.acquire() as conn:
            dt = await conn.fetch(queries["get_all_years_nvd_sync"])
            logger.debug("All years gotten from the nvd_sync table")
    except asyncpg.PostgresError as e:
        logger.error(f"PSQL error: {e}")
    except Exception as e:
        logger.error(f"DB error: {e}")

    res = [i[0] for i in dt] if dt else []
    return res


async def get_nvd_sync_data(year) -> tuple:
    """
    Gets the date (extended ISO-8601 date/time format) of the last time that the database was updated.

    Returns:
        Date of the last time that the vulnerabilities where updated
    """
    dt = ()
    pool = await get_pool()
    try:
        async with pool.acquire() as conn:
            dt = await conn.fetchrow(queries["get_nvd_sync_data"], year)
            logger.debug(f"Last date when {year} CVE data was updated was {dt}")
    except asyncpg.PostgresError as e:
        logger.error(f"PSQL error: {e}")
    except Exception as e:
        logger.error(f"DB error: {e}")
    return dt


async def get_last_fetched_date(year) -> datetime | None:
    """
    Gets the date (extended ISO-8601 date/time format) of the last time that the database was updated.

    Args:
        year: Year identifier or 'recent' for recent updates

    Returns:
        datetime object of last fetch, or None if no sync record exists
    """
    dt = None
    pool = await get_pool()
    try:
        async with pool.acquire() as conn:
            dt = await conn.fetchrow(queries["get_fetch_date"], year)
            if dt:
                logger.debug(f"Last date when CVE data was updated was {dt[0]}")
            else:
                logger.debug("Couldn't fecth the update date")
    except asyncpg.PostgresError as e:
        logger.error(f"PSQL error: {e}")
    except Exception as e:
        logger.error(f"DB error: {e}")

    res = datetime.fromisoformat(dt[0]).astimezone() if dt else None
    return res


async def insert_year_data(value) -> bool:
    """
    Update the date of the last fetched value (extended ISO-8601 date/time format)

    Args:
        value gotten from the last recent file
    Returns:
        Boolean with the result of the query
    """
    res = True
    pool = await get_pool()
    try:
        async with pool.acquire() as conn:
            await conn.execute(queries["insert_fetch_date"], *value)
            logger.debug(f"Last fetched date was updated to {str(value)}")
    except asyncpg.PostgresError as e:
        logger.error(f"PSQL error: {e}")
        res = False
    except Exception as e:
        logger.error(f"DB error: {e}")
        res = False
    return res


async def insert_vulnerabilities(data_cve: list, data_cvss: list) -> dict:
    """
    Inserts bulk data into the DB

    Args:
        NVD json data parsed using function nvd.parse_nvd_data() for CVE and CVSS

    Returns:
        dict structure with 'status' and 'result'
    """
    res = True
    pool = await get_pool()
    try:
        async with pool.acquire() as conn:
            async with conn.transaction():
                await conn.set_type_codec(
                    "jsonb", encoder=json.dumps, decoder=json.loads, schema="pg_catalog"
                )
                await conn.executemany(queries["insert_cve"], data_cve)
                await conn.executemany(queries["insert_cvss"], data_cvss)
    except asyncpg.PostgresError as e:
        logger.error(f"PSQL error: {e}")
        res = False
    except Exception as e:
        logger.error(f"DB error: {e}")
        res = False
    return {"status": res, "result": {"num_cve": len(data_cve)}}


async def get_vulnerabilities_by_id(id: str) -> dict:
    """
    Get vulnerabilities based on CVE ID pattern.

    Returns unique results per CVE with aggregated CVSS metrics from all sources.

    Args:
        id: CVE ID pattern (e.g., "CVE-2025-9951", "CVE-2025-%", "2025")
            Supports SQL ILIKE pattern matching

    Returns:
        dict structure with 'status' and 'result'
        result is a dict keyed by cve_id containing vulnerability details
        with cvss_metrics as a JSON array of all scores from different sources
    """
    res = {"status": True, "result": {}}
    pool = await get_pool()
    try:
        async with pool.acquire() as conn:
            rows = await conn.fetch(queries["get_cves"], id)

        if not rows:
            logger.debug(f"No vulnerabilities found matching pattern: {id}")
            res["status"] = False
            return res

        logger.debug(f"Found {len(rows)} unique vulnerabilities for pattern: {id}")

        # Each row is now unique per CVE (GROUP BY in query)
        # CVSS metrics are JSON-aggregated in row[9]
        for row in rows:
            cve_id = row[0]
            res["result"][cve_id] = {
                "source": row[1],
                "published_date": str(row[2]),
                "last_modified": str(row[3]),
                "status": row[4],
                "references": row[5],
                "descriptions": row[6],
                "weakness": row[7],
                "configurations": row[8],
                "cvss_metrics": row[9],  # Already JSON-aggregated by query
            }

    except asyncpg.PostgresError as e:
        logger.error(f"PSQL error: {e}")
        res = {"status": False, "result": None}
    except Exception as e:
        logger.error(f"DB error: {e}")
        res = {"status": False, "result": None}
    return res


async def get_products(teams: list, id: Optional[str] = None) -> dict:
    """
    Retrieve products.

    Args:
        list of teams (scope)
        id of the product
    Returns:
        dict structure with 'status' and 'result'
    """
    res = {"status": True, "result": []}
    pool = await get_pool()
    try:
        async with pool.acquire() as conn:
            if id:
                q = await conn.fetch(queries["get_product"], id, teams)
            else:
                q = await conn.fetch(queries["get_products"], teams)

        if not q:
            res["status"] = False
        else:
            for p in q:
                res["result"].append({"id": p[0], "description": p[1], "team": p[2]})
    except asyncpg.PostgresError as e:
        logger.error(f"PSQL error: {e}")
        res = {"status": False, "result": None}
    except Exception as e:
        logger.error(f"DB error: {e}")
        res = {"status": False, "result": None}
    return res


async def insert_product(name: str, description: str, team: str) -> dict:
    """
    Inserts a new product

    Args:
        product name (id),
        product description
        team

    Returns:
        dict structure with 'status' and 'result'
    """
    res = {"status": True, "result": None}
    pool = await get_pool()
    try:
        async with pool.acquire() as conn:
            q = await conn.fetchrow(queries["insert_product"], name, description, team)

        if q:
            res["result"] = {"id": q[0]}
            logger.debug(f"New product with name {q[0]} was created")
        else:
            res["status"] = False
            logger.debug("Failed creating the product")
    except asyncpg.PostgresError as e:
        logger.error(f"PSQL error: {e}")
        res = {"status": False, "result": None}
    except Exception as e:
        logger.error(f"DB error: {e}")
        res = {"status": False, "result": None}
    return res


async def delete_product(id: str, team: str) -> dict:
    """
    Delete a product

    Args:
        product id
        team

    Returns:
        dict structure with 'status' and 'result'
    """
    res = {"status": True, "result": None}
    pool = await get_pool()
    try:
        async with pool.acquire() as conn:
            async with conn.transaction():
                q = await conn.execute(queries["delete_product"], id, team)
            if not q.rowcount:
                res["status"] = False
            else:
                res["result"] = {"deleted_rows": q.rowcount}
    except asyncpg.PostgresError as e:
        logger.error(f"PSQL error: {e}")
        res = {"status": False, "result": None}
    except Exception as e:
        logger.error(f"DB error: {e}")
        res = {"status": False, "result": None}
    return res


async def get_images(
    teams: list,
    name: Optional[str] = None,
    version: Optional[str] = None,
    product: Optional[str] = None,
) -> dict:
    """
    Retrieve images, optionally filtered by product.

    Args:
        list of teams
        name
        version
        product

    Returns:
        dict structure with 'status' and 'result'
    """
    res = {"status": True, "result": []}
    pool = await get_pool()
    try:
        async with pool.acquire() as conn:
            if product and name and version:
                q = await conn.fetch(
                    queries["get_images_by_name_version_product"],
                    name,
                    version,
                    product,
                    teams,
                )
            elif product and name:
                q = await conn.fetch(
                    queries["get_images_by_name_product"], name, product, teams
                )
            elif product:
                q = await conn.fetch(queries["get_images_by_product"], product, teams)
            else:
                q = await conn.fetch(queries["get_images"], teams)

        if not q:
            logger.debug("No images were found")
        else:
            logger.debug(f"A total of {len(q)} images were found")
            for im in q:
                res["result"].append(
                    {
                        "name": im[0],
                        "version": im[1],
                        "product": im[2],
                        "team": im[3],
                    }
                )
    except asyncpg.PostgresError as e:
        logger.error(f"PSQL error: {e}")
        res = {"status": False, "result": None}
    except Exception as e:
        logger.error(f"DB error: {e}")
        res = {"status": False, "result": None}
    return res


async def insert_image(name: str, version: str, product: str, team: str) -> dict:
    """
    Inserts a new image

    Args:
        image name
        image description
        product id associated with the image
        team
    Returns:
        dict structure with 'status' and 'result'
    """
    res = {"status": True, "result": {}}
    pool = await get_pool()
    try:
        async with pool.acquire() as conn:
            q = await conn.fetchrow(
                queries["insert_image"], name, version, product, team
            )

        if not q:
            res["status"] = False
            logger.debug(f"Failed created new image with name {name} was created")
        else:
            res["result"] = {
                "name": q[0],
                "version": q[1],
                "product": q[2],
                "team": q[3],
            }
            logger.debug(f"New image with name {q[0]} was created")
    except asyncpg.PostgresError as e:
        logger.error(f"PSQL error: {e}")
        res = {"status": False, "result": None}
    except Exception as e:
        logger.error(f"DB error: {e}")
        res = {"status": False, "result": None}
    return res


async def get_image_vulnerabilities(
    product: str, name: str, version: str, team: str
) -> dict:
    """
    Get the vulnerabilities associated to an image

    Args:
        product
        name
        version
        team
    Returns:
        dict structure with 'status' and 'result'
    """
    res = {"status": True, "result": None}
    pool = await get_pool()
    try:
        async with pool.acquire() as conn:
            q = await conn.fetch(
                queries["get_image_vulnerabilities"], product, name, version, team
            )

        res["result"] = q
        logger.debug(
            f"A total of {len(q)} vulns for image {team}/{product} {name}:{version}"
        )
    except asyncpg.PostgresError as e:
        logger.error(f"PSQL error: {e}")
        res = {"status": False, "result": None}
    except Exception as e:
        logger.error(f"DB error: {e}")
        res = {"status": False, "result": None}
    return res


async def insert_image_vulnerabilities(values: list) -> dict:
    """
    Bind a vulnerability with an image

    Args:
        scanner
        image_name
        image_version
        product
        team
        cve
        fix_versions
        first_seen
        last_seen
        affected_component_type
        affectred_component
        affected_version
        affected_path
    Returns:
        dict structure with 'status' and 'result'
    """
    pool = await get_pool()
    try:
        async with pool.acquire() as conn:
            async with conn.transaction():
                await conn.executemany(queries["insert_image_vulnerabilities"], values)

        logger.debug(f"A total of {len(values)} have been inserted")
        res = {"status": True, "result": {"num_cve": len(values)}}
    except asyncpg.PostgresError as e:
        logger.error(f"PSQL error: {e}")
        res = {"status": False, "result": None}
    except Exception as e:
        logger.error(f"DB error: {e}")
        res = {"status": False, "result": None}
    return res


async def compare_image_versions(
    product: str, image: str, version_a: str, version_b: str, team: str
) -> dict:
    """
    Given two versions for the same product, same image, provide details on the vulnerabilities that are shared and not shared.

    Params:
        product
        image
        version_a
        version_b
        team
    Returns:
        dict structure with 'status' and 'result'
    """
    res = {"status": True, "result": None}
    pool = await get_pool()
    try:
        async with pool.acquire() as conn:
            await conn.set_type_codec(
                "jsonb", encoder=json.dumps, decoder=json.loads, schema="pg_catalog"
            )
            q = await conn.fetch(
                queries["compare_image_versions"],
                team,
                product,
                image,
                version_a,
                version_b,
            )

        if not q:
            res["status"] = False
            logger.debug("Couldn't get data")
        else:
            res["result"] = q
            logger.debug("Data from the two versions gotten")
    except asyncpg.PostgresError as e:
        logger.error(f"PSQL error: {e}")
        res = {"status": False, "result": None}
    except Exception as e:
        logger.error(f"DB error: {e}")
        res = {"status": False, "result": None}
    return res


async def delete_image(team, product, name=None, version=None) -> dict:
    """
    Deletes images

    Args:
        team
        product: id
        name: image name
        version: image version
        team

    Returns:
        dict structure with 'status' and 'result'
    """
    res = {"status": True, "result": None}
    pool = await get_pool()
    try:
        async with pool.acquire() as conn:
            async with conn.transaction():
                q = None
                if version and name:
                    q = await conn.execute(
                        queries["delete_image_by_name_version"],
                        name,
                        version,
                        product,
                        team,
                    )
                elif name:
                    q = await conn.execute(
                        queries["delete_image_by_name"], name, product, team
                    )

            if not q or q.rowcount < 1:
                logger.error(
                    f"Image could not be deleted properly {name} {product} {team}"
                )
                res["status"] = False
            else:
                logger.debug(f"Image was deleted properly {name} {product} {team}")
                res["result"] = {"deleted_rows": q.rowcount}
    except asyncpg.PostgresError as e:
        logger.error(f"PSQL error: {e}")
        res = {"status": False, "result": None}
    except Exception as e:
        logger.error(f"DB error: {e}")
        res = {"status": False, "result": None}
    return res


async def get_users(email=None) -> dict:
    """
    Retrieve users.

    Args:
        email
    Returns:
        dict structure with 'status' and 'result'
    """
    res = {"status": True, "result": []}
    pool = await get_pool()
    try:
        async with pool.acquire() as conn:
            if email:
                q = await conn.fetch(queries["get_users_by_email"], email)
            else:
                q = await conn.fetch(queries["get_users"])
            if not q:
                res["status"] = False
                logger.debug(
                    f"Did not found any users with the given parameters: {email}"
                )
            else:
                logger.debug(f"Found a total of {len(q)} users")
                aux = {}
                for usr in q:
                    aux[usr[0]] = {
                        "name": usr[2],
                        "is_root": usr[3],
                        "scope": {},
                    }
                if email:
                    q = await conn.fetch(
                        queries["get_user_team_scopes_by_email"], email
                    )
                else:
                    q = await conn.fetch(queries["get_user_team_scopes"])
                if not q:
                    logger.debug(
                        f"Did not found any scope with the given parameters: {email}"
                    )
                    res["status"] = False
                else:
                    for sc in q:
                        aux[sc[0]]["scope"][sc[1]] = sc[2]

                    for k, v in aux.items():
                        aux = {
                            "email": k,
                            "name": v["name"],
                            "is_root": v["is_root"],
                            "scope": v["scope"],
                        }
                        res["result"].append(aux)
    except asyncpg.PostgresError as e:
        logger.error(f"PSQL error: {e}")
        res = {"status": False, "result": None}
    except Exception as e:
        logger.error(f"DB error: {e}")
        res = {"status": False, "result": None}
    return res


async def get_users_w_hpass(email) -> dict:
    """
    Retrieve users.

    Args:
        email
    Returns:
        dict structure with 'status' and 'result'
    """
    res = {"status": True, "result": []}
    pool = await get_pool()
    try:
        async with pool.acquire() as conn:
            q = await conn.fetch(queries["get_users_by_email"], email)
            if not q:
                res["status"] = False
                logger.debug(
                    f"Did not found any users with the given parameters: {email}"
                )
            else:
                logger.debug(f"Found a total of {len(q)} users")
                aux = {}
                for usr in q:
                    aux[usr[0]] = {
                        "hpass": usr[1],
                        "name": usr[2],
                        "is_root": usr[3],
                        "scope": {},
                    }
                q = await conn.fetch(queries["get_user_team_scopes_by_email"], email)
                if not q:
                    logger.debug(
                        f"Did not found any scope with the given parameters: {email}"
                    )
                    res["status"] = False
                else:
                    for sc in q:
                        aux[sc[0]]["scope"][sc[1]] = sc[2]

                    for k, v in aux.items():
                        aux = {
                            "email": k,
                            "hpass": v["hpass"],
                            "name": v["name"],
                            "is_root": v["is_root"],
                            "scope": v["scope"],
                        }
                        res["result"].append(aux)
    except asyncpg.PostgresError as e:
        logger.error(f"PSQL error: {e}")
        res = {"status": False, "result": None}
    except Exception as e:
        logger.error(f"DB error: {e}")
        res = {"status": False, "result": None}
    return res


async def insert_users(email, password, name, scopes, is_root=False) -> dict:
    """
    Insert an user

    Args:
        email
        name
        password
        scopes: dict with team-scope bindings
    Returns:
        dict structure with 'status' and 'result'
    """
    pool = await get_pool()
    try:
        async with pool.acquire() as conn:
            await conn.execute(queries["insert_users"], email, password, name, is_root)
            for t, s in scopes.items():
                await conn.execute(queries["insert_user_team_scopes"], email, t, s)

        logger.debug(f"A new user {email} has been added")
        res = {"status": True, "result": {"user": email}}
    except asyncpg.PostgresError as e:
        logger.error(f"PSQL error: {e}")
        res = {"status": False, "result": None}
    except Exception as e:
        logger.error(f"DB error: {e}")
        res = {"status": False, "result": None}
    return res


async def update_users(
    email, password=None, name=None, scopes=None, is_root=None
) -> dict:
    """
    Update a user

    Args:
        email: user email (identifier)
        password: new hashed password (optional)
        name: new name (optional)
        scopes: dict with team-scope bindings (optional)
        is_root: root privilege flag (optional)

    Returns:
        dict structure with 'status' and 'result'
    """
    res = {"status": True, "result": {"user": email}}
    pool = await get_pool()

    try:
        async with pool.acquire() as conn:
            async with conn.transaction():
                # Handle common cases with predefined queries
                if password and not name and is_root is None:
                    await conn.execute(queries["update_user_password"], password, email)
                elif name and not password and is_root is None:
                    await conn.execute(queries["update_user_name"], name, email)
                elif is_root is not None and not password and not name:
                    await conn.execute(queries["update_user_root"], is_root, email)
                elif password and name and is_root is None:
                    await conn.execute(
                        queries["update_user_password_name"], password, name, email
                    )

                else:
                    # Edge case: multiple fields or complex combinations
                    # Build query dynamically with correct $N notation
                    update_fields = []
                    fields = []
                    param_idx = 1

                    if password:
                        update_fields.append(f"hpass = ${param_idx}")
                        fields.append(password)
                        param_idx += 1

                    if name:
                        update_fields.append(f"name = ${param_idx}")
                        fields.append(name)
                        param_idx += 1

                    if is_root is not None:
                        update_fields.append(f"is_root = ${param_idx}")
                        fields.append(is_root)
                        param_idx += 1

                    if update_fields:
                        q = f"UPDATE users SET {', '.join(update_fields)} WHERE email = ${param_idx};"
                        fields.append(email)
                        await conn.execute(q, *fields)

                # Handle scope updates (separate from user table)
                if scopes:
                    logger.debug("updating scopes")
                    for t, s in scopes.items():
                        logger.debug(f"team: {t}; scope: {s}")
                        await conn.execute(
                            queries["insert_user_team_scopes"], email, t, s
                        )

        logger.debug(f"User {email} has been updated")

    except asyncpg.PostgresError as e:
        logger.error(f"PSQL error: {e}")
        res = {"status": False, "result": str(e)}
    except Exception as e:
        logger.error(f"DB error: {e}")
        res = {"status": False, "result": str(e)}

    return res


async def delete_user(email) -> dict:
    """
    Deletes user

    Args:
        email: id

    Returns:
        dict structure with 'status' and 'result'
    """
    res = {"status": True, "result": None}
    pool = await get_pool()
    try:
        async with pool.acquire() as conn:
            async with conn.transaction():
                q = await conn.execute(queries["delete_user_by_email"], email)
            if not q.rowcount:
                res["status"] = False
            else:
                res["result"] = {"deleted_rows": q.rowcount}
    except asyncpg.PostgresError as e:
        logger.error(f"PSQL error: {e}")
        res = {"status": False, "result": None}
    except Exception as e:
        logger.error(f"DB error: {e}")
        res = {"status": False, "result": None}
    return res


async def get_teams(name=None) -> dict:
    """
    Retrieve teams.

    Args:
        name
    Returns:
        dict structure with 'status' and 'result'
    """
    res = {"status": True, "result": []}
    pool = await get_pool()
    try:
        async with pool.acquire() as conn:
            if name:
                q = await conn.fetch(queries["get_teams_by_name"], name)
            else:
                q = await conn.fetch(queries["get_teams"])

        if not q:
            logger.debug("No teams where identified")
        else:
            logger.debug(f"A total of {len(q)} teams were identified")
            for t in q:
                res["result"].append({"name": t[0], "description": t[1]})
    except asyncpg.PostgresError as e:
        logger.error(f"PSQL error: {e}")
        res = {"status": False, "result": None}
    except Exception as e:
        logger.error(f"DB error: {e}")
        res = {"status": False, "result": None}
    return res


async def insert_teams(name: str, description: str = "") -> dict:
    """
    Insert a team

    Args:
        name
        description
    Returns:
        dict structure with 'status' and 'result'
    """
    res = {"status": True, "result": None}
    pool = await get_pool()
    try:
        async with pool.acquire() as conn:
            q = await conn.fetchrow(queries["insert_teams"], name, description)

        if q:
            res["result"] = {}
            res["result"]["name"] = q[0]
            logger.debug(f"A new team with name {q} has been added")
        else:
            logger.debug("Failed adding the team")
    except asyncpg.PostgresError as e:
        logger.error(f"PSQL error: {e}")
        res["result"] = False
    except Exception as e:
        logger.error(f"DB error: {e}")
        res["result"] = False
    return res


async def delete_team(id) -> dict:
    """
    Deletes a team

    Args:
        id

    Returns:
        dict structure with 'status' and 'result'
    """
    res = {"status": True, "result": None}
    pool = await get_pool()
    try:
        async with pool.acquire() as conn:
            async with conn.transaction():
                q = await conn.execute(queries["delete_teams"], id)
            if not q.rowcount:
                logger.error(f"Team with id {id} could not be removed")
                res["status"] = False
            else:
                logger.debug(f"Team with id {id} was removed")
                res["result"] = {"deleted_rows": q.rowcount}
    except asyncpg.PostgresError as e:
        logger.error(f"PSQL error: {e}")
        res = {"status": False, "result": None}
    except Exception as e:
        logger.error(f"DB error: {e}")
        res = {"status": False, "result": None}
    return res


async def get_scope_by_user(email=None) -> dict:
    pool = await get_pool()
    res = {"status": True, "result": None}
    try:
        async with pool.acquire() as conn:
            if email:
                q = await conn.fetch(queries["get_user_team_scopes_by_email"], email)
            else:
                q = await conn.fetch(queries["get_user_team_scopes"])

            if not q:
                logger.error("Scopes for users could not be identified")
                res["status"] = False
            else:
                logger.debug("Scopes for users were identified")
                res["result"] = {}
                for r in q:
                    res["result"][r[1]] = r[2]
    except asyncpg.PostgresError as e:
        logger.error(f"PSQL error: {e}")
        res = {"status": False, "result": None}
    except Exception as e:
        logger.error(f"DB error: {e}")
        res = {"status": False, "result": None}
    return res


async def insert_api_token(
    token_hash: str,
    prefix: str,
    user_email: str,
    description: Optional[str] = None,
    expires_at: Optional[datetime] = None,
) -> dict:
    """
    Create new API token.
    Token inherits all permissions from the user.

    Args:
        token_hash: Argon2 hash of the token
        prefix: First 12 characters of token (for display)
        user_email: User who owns the token
        description: Optional description
        expires_at: Optional expiration timestamp

    Returns:
        dict: {"status": bool, "result": {id, prefix, created_at} or error}
    """
    res = {"status": False, "result": None}
    pool = await get_pool()
    try:
        async with pool.acquire() as conn:
            q = await conn.fetchrow(
                queries["insert_api_token"],
                token_hash,
                prefix,
                user_email,
                description,
                expires_at,
            )

        if not q:
            raise Exception("API token could not be created")

        res["status"] = True
        res["result"] = {}
        res["result"]["id"] = q[0]
        res["result"]["prefix"] = q[1]
        res["result"]["created_at"] = q[2]
    except Exception as e:
        logger.error(f"Error inserting API token: {e}")
        res["result"] = str(e)
    return res


async def get_api_token_by_hash(token_hash: str) -> dict:
    """
    Get API token by hash for validation.

    Args:
        token_hash: Hash of the token

    Returns:
        dict: {"status": bool, "result": token_data or error}
    """
    res = {"status": False, "result": None}
    pool = await get_pool()
    try:
        async with pool.acquire() as conn:
            q = await conn.fetchrow(queries["get_api_token_by_hash"], token_hash)

        if not q:
            logger.debug("Token not found")
            res["result"] = "Token not found"
            res["status"] = True
            return res

        res["status"] = True
        res["result"] = {
            "id": q[0],
            "token_hash": q[1],
            "user_email": q[2],
            "revoked": q[3],
            "expires_at": q[4],
            "last_used_at": q[5],
            "description": q[6],
        }
    except Exception as e:
        logger.error(f"Error getting API token: {e}")
        res["result"] = str(e)
    return res


async def get_api_token_by_prefix(prefix: str) -> dict:
    """
    Get API token by prefix for validation.

    Args:
        prefix: First 12 characters of the token

    Returns:
        dict: {"status": bool, "result": token_data or error}
    """
    res = {"status": False, "result": None}
    pool = await get_pool()
    try:
        async with pool.acquire() as conn:
            q = await conn.fetchrow(queries["get_api_token_by_prefix"], prefix)

        if not q:
            logger.debug("Token not found")
            res["status"] = False
            res["result"] = "Token not found"
            return res

        res["status"] = True
        res["result"] = {
            "id": q[0],
            "token_hash": q[1],
            "user_email": q[2],
            "revoked": q[3],
            "expires_at": q[4],
            "last_used_at": q[5],
            "description": q[6],
        }
    except Exception as e:
        logger.error(f"Error getting API token by prefix: {e}")
        res["result"] = str(e)
    return res


async def get_api_token_by_id(token_id: int) -> dict:
    """Get API token by ID."""
    res = {"status": False, "result": None}
    pool = await get_pool()
    try:
        async with pool.acquire() as conn:
            q = await conn.fetchrow(queries["get_api_token_by_id"], token_id)

        if not q:
            logger.debug("Token not found")
            res["result"] = "Token not found"
            return res

        res = {
            "status": True,
            "result": {
                "id": q[0],
                "prefix": q[1],
                "user_email": q[2],
                "description": q[3],
                "created_at": q[4],
                "last_used_at": q[5],
                "expires_at": q[6],
                "revoked": q[7],
            },
        }
    except Exception as e:
        logger.error(f"Error getting API token: {e}")
        res["result"] = str(e)
    return res


async def list_api_tokens(user_email: Optional[str] = None) -> dict:
    """
    List API tokens.

    Args:
        user_email: Filter by user (None for all users)

    Returns:
        dict: {"status": bool, "result": list of tokens or error}
    """
    res = {"status": False, "result": None}
    pool = await get_pool()
    try:
        async with pool.acquire() as conn:
            if not user_email:
                q = await conn.fetch(queries["list_all_api_tokens"])
            else:
                q = await conn.fetch(queries["list_api_tokens_by_user"], user_email)

        if q:
            tokens = []
            for row in q:
                tokens.append(
                    {
                        "id": row[0],
                        "prefix": row[1],
                        "user_email": row[2],
                        "description": row[3],
                        "created_at": row[4],
                        "last_used_at": row[5],
                        "expires_at": row[6],
                        "revoked": row[7],
                    }
                )

            res["status"] = True
            res["result"] = tokens
        else:
            res["status"] = True
            res["result"] = []
    except Exception as e:
        logger.error(f"Error getting API token: {e}")
        res["result"] = "Could not fetch tokens"
    return res


async def revoke_api_token(
    token_id: int, user_email: Optional[str] = None, admin: bool = False
) -> dict:
    """
    Revoke an API token.

    Args:
        token_id: ID of token to revoke
        user_email: User requesting revocation (for permission check)
        admin: If True, skip user ownership check

    Returns:
        dict: {"status": bool, "result": success message or error}
    """
    res = {"status": False, "result": None}
    pool = await get_pool()
    try:
        async with pool.acquire() as conn:
            async with conn.transaction():
                if admin:
                    q = await conn.fetchrow(queries["revoke_api_token_admin"], token_id)
                else:
                    q = await conn.fetchrow(
                        queries["revoke_api_token"], token_id, user_email
                    )

        if not q:
            logger.error("Token could not be revoked")
            res["result"] = "Token could not be revoked"
            return res

        res["status"] = True
        res["result"] = "Token revoked successfully"
    except Exception as e:
        logger.error(f"Error revoking API token: {e}")
        res["result"] = str(e)
    return res


async def update_token_last_used(token_id: int) -> dict:
    """
    Update last_used_at timestamp for a token.

    Args:
        token_id: ID of token to update

    Returns:
        dict: {"status": bool}
    """
    res = {"status": False, "result": None}
    pool = await get_pool()
    try:
        async with pool.acquire() as conn:
            async with conn.transaction():
                await conn.execute(queries["update_token_last_used"], token_id)

        res["status"] = True
        res["result"] = "Token updated successfully"
    except Exception as e:
        logger.error(f"Error updating API token: {e}")
        res["result"] = str(e)
    return res


async def insert_osv_data(
    data_vuln: list,
    data_aliases: list,
    data_refs: list,
    data_severity: list,
    data_affected: list,
    data_credits: list,
) -> dict:
    """
    Inserts OSV (Open Source Vulnerability) data into the database.

    Args:
        data_vuln: List of tuples for osv_vulnerabilities table
            (osv_id, schema_version, modified, published, withdrawn, summary, details, database_specific)
        data_aliases: List of tuples for osv_aliases table
            (osv_id, alias)
        data_refs: List of tuples for osv_references table
            (osv_id, ref_type, url)
        data_severity: List of tuples for osv_severity table
            (osv_id, severity_type, score)
        data_affected: List of tuples for osv_affected table
            (osv_id, package_ecosystem, package_name, package_purl, ranges, versions, ecosystem_specific, database_specific)
        data_credits: List of tuples for osv_credits table
            (osv_id, name, contact, credit_type)

    Returns:
        dict structure with 'status' and 'result'
    """
    res = True
    osv_id = data_vuln[0][0] if data_vuln else None
    pool = await get_pool()
    try:
        async with pool.acquire() as conn:
            if data_vuln:
                async with conn.transaction():
                    await conn.executemany(
                        queries["insert_osv_vulnerability"], data_vuln
                    )

            if data_aliases:
                async with conn.transaction():
                    await conn.executemany(queries["insert_osv_alias"], data_aliases)

            # For updates, delete existing child records and re-insert
            # This ensures data consistency when OSV entries are updated
            if osv_id:
                await conn.execute(queries["delete_osv_references"], osv_id)
                await conn.execute(queries["delete_osv_severity"], osv_id)
                await conn.execute(queries["delete_osv_affected"], osv_id)
                await conn.execute(queries["delete_osv_credits"], osv_id)

            # Insert child records
            if data_refs:
                async with conn.transaction():
                    await conn.executemany(queries["insert_osv_reference"], data_refs)

            if data_severity:
                async with conn.transaction():
                    await conn.executemany(
                        queries["insert_osv_severity"], data_severity
                    )

            if data_affected:
                async with conn.transaction():
                    await conn.executemany(
                        queries["insert_osv_affected"], data_affected
                    )

            if data_credits:
                async with conn.transaction():
                    await conn.executemany(queries["insert_osv_credit"], data_credits)

            logger.info(
                f"Inserted OSV {osv_id}: {len(data_aliases)} aliases, {len(data_refs)} refs, "
                f"{len(data_severity)} severity, {len(data_affected)} affected, {len(data_credits)} credits"
            )
    except asyncpg.PostgresError as e:
        logger.error(f"PSQL error inserting OSV data: {e}")
        res = False
    except Exception as e:
        logger.error(f"Error inserting OSV data: {e}")
        res = False
    return {"status": res, "result": {"osv_id": osv_id}}


async def get_osv_by_id(osv_id: str) -> dict:
    """
    Get OSV vulnerability by OSV ID.

    Args:
        osv_id: The OSV identifier (e.g., "OSV-2024-001", "GHSA-xxxx-yyyy-zzzz")

    Returns:
        dict structure with 'status' and 'result'
        result contains: {osv_id, schema_version, modified, published, withdrawn, summary, details, database_specific}
    """
    res = {"status": False, "result": None}
    pool = await get_pool()
    try:
        async with pool.acquire() as conn:
            await conn.set_type_codec(
                "jsonb", encoder=json.dumps, decoder=json.loads, schema="pg_catalog"
            )
            q = await conn.fetchrow(queries["get_osv_by_id"], osv_id)

        if not q:
            logger.debug(f"OSV {osv_id} not found in database")
            res["status"] = False
            res["result"] = None
        else:
            res["status"] = True
            res["result"] = {
                "osv_id": q[0],
                "schema_version": q[1],
                "modified": q[2],
                "published": q[3],
                "withdrawn": q[4],
                "summary": q[5],
                "details": q[6],
                "database_specific": q[7],
            }
            logger.debug(f"Found OSV {osv_id} in database")
    except asyncpg.PostgresError as e:
        logger.error(f"PSQL error getting OSV: {e}")
        res["status"] = False
    except Exception as e:
        logger.error(f"Error getting OSV: {e}")
        res["status"] = False
    return res


async def get_osv_by_ilike_id(osv_id: str) -> dict:
    """
    Get OSV vulnerabilities by OSV ID pattern with severity data.

    Returns unique results per vulnerability ID with aggregated severity data.

    Args:
        osv_id: The OSV identifier pattern (e.g., "2025", "GHSA-xxxx", "PYSEC-2024")
                Supports SQL ILIKE pattern matching (% wildcards)

    Returns:
        dict structure with 'status' and 'result'
        result contains array of: {osv_id, schema_version, modified, published, withdrawn, summary, details, database_specific, severity}
        severity is a JSON array of {type, score} objects
    """
    res = {"status": False, "result": None}
    pool = await get_pool()
    try:
        async with pool.acquire() as conn:
            await conn.set_type_codec(
                "jsonb", encoder=json.dumps, decoder=json.loads, schema="pg_catalog"
            )
            rows = await conn.fetch(queries["get_osvs"], osv_id)

        if not rows:
            logger.debug(f"No OSV vulnerabilities found matching pattern: {osv_id}")
            res["status"] = False
            res["result"] = []
        else:
            res["status"] = True
            res["result"] = []

            # Each row is now unique per osv_id (GROUP BY in query)
            # Severity data is JSON-aggregated in row[8]
            for row in rows:
                osv_entry = {
                    "osv_id": row[0],
                    "schema_version": row[1],
                    "modified": row[2],
                    "published": row[3],
                    "withdrawn": row[4],
                    "summary": row[5],
                    "details": row[6],
                    "database_specific": row[7],
                    "severity": row[8],  # Already JSON-aggregated by query
                }
                res["result"].append(osv_entry)

            logger.debug(
                f"Found {len(res['result'])} unique OSV results for pattern: {osv_id}"
            )
    except asyncpg.PostgresError as e:
        logger.error(f"PSQL error getting OSV: {e}")
        res["status"] = False
        res["result"] = []
    except Exception as e:
        logger.error(f"Error getting OSV: {e}")
        res["status"] = False
        res["result"] = []
    return res


async def insert_vulnerability_sca(
    vuln: dict,
    image_name: str,
    image_version: str,
    product: str,
    team: str,
    scanner: str,
) -> dict:
    """
    Insert or update a vulnerability record in universal SCA format.

    Args:
        vuln: Dict containing vulnerability data in universal format
        image_name: Name of the container image
        image_version: Version of the container image
        product: Product ID
        team: Team name

    Returns:
        dict structure with 'status' and 'result'
    """
    res = {"status": True, "result": "Vulnerability inserted"}
    pool = await get_pool()
    try:
        # Extract severity data from universal format
        severity = vuln.get("severity", {})
        severity_level = severity.get("level", "Unknown")
        cvss = severity.get("cvss", [])
        epss = severity.get("epss", [])
        risk_score = severity.get("risk_score")
        vuln_id = vuln.get("vuln_id", "")

        async with pool.acquire() as conn:
            await conn.set_type_codec(
                "jsonb", encoder=json.dumps, decoder=json.loads, schema="pg_catalog"
            )
            await conn.execute(
                queries["insert_vulnerability_sca"],
                scanner,
                vuln_id,
                vuln.get("source", ""),
                image_name,
                image_version,
                product,
                team,
                vuln.get("description", ""),
                severity_level,
                vuln.get("affected_component_type", ""),
                vuln.get("affected_component", ""),
                vuln.get("affected_version", ""),
                vuln.get("affected_path", ""),
                json.dumps(cvss),
                json.dumps(epss),
                json.dumps(vuln.get("urls", [])),
                json.dumps(vuln.get("cwes", [])),
                json.dumps(vuln.get("fix", {})),
                json.dumps(vuln.get("related_vulnerabilities", [])),
                # Universal format fields
                vuln.get("purl"),
                vuln.get("namespace"),
                risk_score,
                json.dumps(vuln.get("cpes", [])),
                json.dumps(vuln.get("licenses", [])),
                json.dumps(vuln.get("locations", [])),
                json.dumps(vuln.get("upstreams", [])),
                json.dumps(vuln.get("match_details", [])),
            )
        logger.debug(
            f"Inserted vulnerability {vuln_id} for image {image_name}:{image_version}"
        )
    except asyncpg.PostgresError as e:
        logger.error(f"PSQL error in insert_vulnerability_sca: {e}")
        res = {"status": False, "result": str(e)}
    except Exception as e:
        logger.error(f"Error in insert_vulnerability_sca: {e}")
        res = {"status": False, "result": str(e)}
    return res


async def insert_vulnerabilities_sca_batch(
    vulns: list[dict],
    image_name: str,
    image_version: str,
    product: str,
    team: str,
    scanner: str,
) -> dict:
    """
    Batch insert multiple vulnerability records in universal SCA format.

    Args:
        vulns: List of dicts containing vulnerability data in universal format
        image_name: Name of the container image
        image_version: Version of the container image
        product: Product ID
        team: Team name
        scanner: Scanner name (e.g., "grype")

    Returns:
        dict structure with 'status' and 'result'
    """
    res = {"status": True, "result": f"Inserted {len(vulns)} vulnerabilities"}
    pool = await get_pool()
    try:
        values = []
        for v in vulns:
            # Extract severity data from universal format
            severity = v.get("severity", {})
            severity_level = severity.get("level", "Unknown")
            cvss = severity.get("cvss", [])
            epss = severity.get("epss", [])
            risk_score = severity.get("risk_score")

            values.append(
                (
                    scanner,
                    v.get("vuln_id", ""),
                    v.get("source", ""),
                    image_name,
                    image_version,
                    product,
                    team,
                    v.get("description", ""),
                    severity_level,
                    v.get("affected_component_type", ""),
                    v.get("affected_component", ""),
                    v.get("affected_version", ""),
                    v.get("affected_path", ""),
                    json.dumps(cvss),
                    json.dumps(epss),
                    json.dumps(v.get("urls", [])),
                    json.dumps(v.get("cwes", [])),
                    json.dumps(v.get("fix", {})),
                    json.dumps(v.get("related_vulnerabilities", [])),
                    # Universal format fields
                    v.get("purl"),
                    v.get("namespace"),
                    risk_score,
                    json.dumps(v.get("cpes", [])),
                    json.dumps(v.get("licenses", [])),
                    json.dumps(v.get("locations", [])),
                    json.dumps(v.get("upstreams", [])),
                    json.dumps(v.get("match_details", [])),
                )
            )

        async with pool.acquire() as conn:
            await conn.executemany(queries["insert_vulnerability_sca"], values)

        logger.debug(
            f"Batch inserted {len(vulns)} vulnerabilities for {image_name}:{image_version}"
        )
    except asyncpg.PostgresError as e:
        logger.error(f"PSQL error in insert_vulnerabilities_sca_batch: {e}")
        res = {"status": False, "result": str(e)}
    except Exception as e:
        logger.error(f"Error in insert_vulnerabilities_sca_batch: {e}")
        res = {"status": False, "result": str(e)}
    return res


async def get_vulnerabilities_sca_by_image(
    image_name: str,
    image_version: str,
    product: str,
    team: str,
) -> dict:
    """
    Get all vulnerability records for an image in universal SCA format.

    Args:
        image_name: Name of the container image
        image_version: Version of the container image
        product: Product ID
        team: Team name

    Returns:
        dict structure with 'status' and 'result' containing list of vulnerabilities
    """
    res = {"status": True, "result": []}
    pool = await get_pool()
    try:
        async with pool.acquire() as conn:
            await conn.set_type_codec(
                "jsonb", encoder=json.dumps, decoder=json.loads, schema="pg_catalog"
            )
            rows = await conn.fetch(
                queries["get_vulnerabilities_sca_by_image"],
                image_name,
                image_version,
                product,
                team,
            )

        if rows:
            for row in rows:
                res["result"].append(
                    {
                        "scanner": row[0],
                        "vuln_id": row[1],
                        "source": row[2],
                        "description": row[3],
                        "severity_level": row[4],
                        "affected_component_type": row[5],
                        "affected_component": row[6],
                        "affected_version": row[7],
                        "affected_path": row[8],
                        "cvss": row[9],
                        "epss": row[10],
                        "urls": row[11],
                        "cwes": row[12],
                        "fix": row[13],
                        "related_vulnerabilities": row[14],
                        # Universal format fields
                        "purl": row[15],
                        "namespace": row[16],
                        "risk_score": row[17],
                        "cpes": row[18],
                        "licenses": row[19],
                        "locations": row[20],
                        "upstreams": row[21],
                        "match_details": row[22],
                    }
                )
        logger.debug(
            f"Found {len(res['result'])} SCA vulnerabilities for {image_name}:{image_version}"
        )
    except asyncpg.PostgresError as e:
        logger.error(f"PSQL error in get_vulnerabilities_sca_by_image: {e}")
        res = {"status": False, "result": str(e)}
    except Exception as e:
        logger.error(f"Error in get_vulnerabilities_sca_by_image: {e}")
        res = {"status": False, "result": str(e)}
    return res


async def get_vulnerability_sca_by_id(vuln_id: str, team: str) -> dict:
    """
    Get vulnerability records by ID within a team in universal SCA format.

    Args:
        vuln_id: Vulnerability ID (e.g., CVE-2024-1234)
        team: Team name

    Returns:
        dict structure with 'status' and 'result' containing list of vulnerabilities
    """
    res = {"status": True, "result": []}
    pool = await get_pool()
    try:
        async with pool.acquire() as conn:
            await conn.set_type_codec(
                "jsonb", encoder=json.dumps, decoder=json.loads, schema="pg_catalog"
            )
            rows = await conn.fetch(
                queries["get_vulnerability_sca_by_id"],
                vuln_id,
                team,
            )

        if rows:
            for row in rows:
                res["result"].append(
                    {
                        "scanner": row[0],
                        "vuln_id": row[1],
                        "source": row[2],
                        "image_name": row[3],
                        "image_version": row[4],
                        "product": row[5],
                        "team": row[6],
                        "description": row[7],
                        "severity_level": row[8],
                        "affected_component_type": row[9],
                        "affected_component": row[10],
                        "affected_version": row[11],
                        "affected_path": row[12],
                        "cvss": row[13],
                        "epss": row[14],
                        "urls": row[15],
                        "cwes": row[16],
                        "fix": row[17],
                        "related_vulnerabilities": row[18],
                        # Universal format fields
                        "purl": row[19],
                        "namespace": row[20],
                        "risk_score": row[21],
                        "cpes": row[22],
                        "licenses": row[23],
                        "locations": row[24],
                        "upstreams": row[25],
                        "match_details": row[26],
                    }
                )
        logger.debug(
            f"Found {len(res['result'])} SCA vulnerabilities for {vuln_id} in team {team}"
        )
    except asyncpg.PostgresError as e:
        logger.error(f"PSQL error in get_vulnerability_sca_by_id: {e}")
        res = {"status": False, "result": str(e)}
    except Exception as e:
        logger.error(f"Error in get_vulnerability_sca_by_id: {e}")
        res = {"status": False, "result": str(e)}
    return res


def _row_to_sast_dict(row) -> dict:
    """Convert an asyncpg Row from vulnerabilities_sast to a dict."""
    return {
        "scanner": row[0],
        "rule_id": row[1],
        "product": row[2],
        "team": row[3],
        "file_path": row[4],
        "start_line": row[5],
        "start_col": row[6],
        "end_line": row[7],
        "end_col": row[8],
        "message": row[9],
        "severity": row[10],
        "confidence": row[11],
        "code_snippet": row[12],
        "suggested_fix": row[13],
        "fingerprint": row[14],
        "cwes": row[15],
        "owasp": row[16],
        "refs": row[17],
        "category": row[18],
        "subcategory": row[19],
        "technology": row[20],
        "vulnerability_class": row[21],
        "impact": row[22],
        "likelihood": row[23],
        "engine_kind": row[24],
        "validation_state": row[25],
        "first_seen": str(row[26]) if row[26] else None,
        "last_seen": str(row[27]) if row[27] else None,
    }


async def insert_vulnerabilities_sast_batch(
    findings: list[dict],
    product: str,
    team: str,
    scanner: str,
) -> dict:
    """
    Batch insert SAST findings.

    Args:
        findings: List of finding dicts from semgrep_parser
        product: Product ID
        team: Team name
        scanner: Scanner name (e.g., 'semgrep')

    Returns:
        dict structure with 'status' and 'result'
    """
    res = {"status": True, "result": f"Inserted {len(findings)} SAST findings"}
    pool = await get_pool()
    try:
        values = []
        for f in findings:
            values.append(
                (
                    scanner,
                    f["rule_id"],
                    product,
                    team,
                    f["file_path"],
                    f["start_line"],
                    f["start_col"],
                    f["end_line"],
                    f["end_col"],
                    f.get("message", ""),
                    f["severity"],
                    f.get("confidence", ""),
                    f.get("code_snippet", ""),
                    f.get("suggested_fix", ""),
                    f.get("fingerprint", ""),
                    json.dumps(f.get("cwes", [])),
                    json.dumps(f.get("owasp", [])),
                    json.dumps(f.get("refs", [])),
                    f.get("category", ""),
                    json.dumps(f.get("subcategory", [])),
                    json.dumps(f.get("technology", [])),
                    json.dumps(f.get("vulnerability_class", [])),
                    f.get("impact", ""),
                    f.get("likelihood", ""),
                    f.get("engine_kind", ""),
                    f.get("validation_state", ""),
                )
            )

        async with pool.acquire() as conn:
            await conn.executemany(queries["insert_vulnerability_sast"], values)

        logger.debug(
            f"Batch inserted {len(findings)} SAST findings for {product} in team {team}"
        )
    except asyncpg.PostgresError as e:
        logger.error(f"PSQL error in insert_vulnerabilities_sast_batch: {e}")
        res = {"status": False, "result": str(e)}
    except Exception as e:
        logger.error(f"Error in insert_vulnerabilities_sast_batch: {e}")
        res = {"status": False, "result": str(e)}
    return res


async def get_vulnerabilities_sast_by_product(product: str, team: str) -> dict:
    """
    Get all SAST findings for a product.

    Args:
        product: Product ID
        team: Team name

    Returns:
        dict structure with 'status' and 'result'
    """
    res = {"status": True, "result": []}
    pool = await get_pool()
    try:
        async with pool.acquire() as conn:
            await conn.set_type_codec(
                "jsonb", encoder=json.dumps, decoder=json.loads, schema="pg_catalog"
            )
            rows = await conn.fetch(
                queries["get_vulnerabilities_sast_by_product"], product, team
            )

        if rows:
            for row in rows:
                res["result"].append(_row_to_sast_dict(row))
        logger.debug(
            f"Found {len(res['result'])} SAST findings for {product} in team {team}"
        )
    except asyncpg.PostgresError as e:
        logger.error(f"PSQL error in get_vulnerabilities_sast_by_product: {e}")
        res = {"status": False, "result": str(e)}
    except Exception as e:
        logger.error(f"Error in get_vulnerabilities_sast_by_product: {e}")
        res = {"status": False, "result": str(e)}
    return res


async def get_vulnerabilities_sast_by_team(team: str) -> dict:
    """
    Get all SAST findings for a team across all products.

    Args:
        team: Team name

    Returns:
        dict structure with 'status' and 'result'
    """
    res = {"status": True, "result": []}
    pool = await get_pool()
    try:
        async with pool.acquire() as conn:
            await conn.set_type_codec(
                "jsonb", encoder=json.dumps, decoder=json.loads, schema="pg_catalog"
            )
            rows = await conn.fetch(queries["get_vulnerabilities_sast_by_team"], team)

        if rows:
            for row in rows:
                res["result"].append(_row_to_sast_dict(row))
        logger.debug(f"Found {len(res['result'])} SAST findings for team {team}")
    except asyncpg.PostgresError as e:
        logger.error(f"PSQL error in get_vulnerabilities_sast_by_team: {e}")
        res = {"status": False, "result": str(e)}
    except Exception as e:
        logger.error(f"Error in get_vulnerabilities_sast_by_team: {e}")
        res = {"status": False, "result": str(e)}
    return res


async def get_vulnerability_sast_by_rule(rule_id: str, team: str) -> dict:
    """
    Get SAST findings by rule ID within a team.

    Args:
        rule_id: Semgrep rule ID
        team: Team name

    Returns:
        dict structure with 'status' and 'result'
    """
    res = {"status": True, "result": []}
    pool = await get_pool()
    try:
        async with pool.acquire() as conn:
            await conn.set_type_codec(
                "jsonb", encoder=json.dumps, decoder=json.loads, schema="pg_catalog"
            )
            rows = await conn.fetch(
                queries["get_vulnerability_sast_by_rule"], rule_id, team
            )

        if rows:
            for row in rows:
                res["result"].append(_row_to_sast_dict(row))
        logger.debug(
            f"Found {len(res['result'])} SAST findings for rule {rule_id} in team {team}"
        )
    except asyncpg.PostgresError as e:
        logger.error(f"PSQL error in get_vulnerability_sast_by_rule: {e}")
        res = {"status": False, "result": str(e)}
    except Exception as e:
        logger.error(f"Error in get_vulnerability_sast_by_rule: {e}")
        res = {"status": False, "result": str(e)}
    return res


async def delete_vulnerabilities_sast_by_product(product: str, team: str) -> dict:
    """
    Delete all SAST findings for a product.

    Args:
        product: Product ID
        team: Team name

    Returns:
        dict structure with 'status' and 'result'
    """
    res = {"status": True, "result": None}
    pool = await get_pool()
    try:
        async with pool.acquire() as conn:
            async with conn.transaction():
                q = await conn.execute(
                    queries["delete_vulnerabilities_sast_by_product"], product, team
                )
            res["result"] = {"deleted_rows": int(q.split()[-1])}
            logger.debug(f"Deleted SAST findings for {product} in team {team}")
    except asyncpg.PostgresError as e:
        logger.error(f"PSQL error in delete_vulnerabilities_sast_by_product: {e}")
        res = {"status": False, "result": str(e)}
    except Exception as e:
        logger.error(f"Error in delete_vulnerabilities_sast_by_product: {e}")
        res = {"status": False, "result": str(e)}
    return res


async def get_sast_stats_by_team(team: str) -> dict:
    """
    Get SAST finding statistics by team, broken down by product and severity.

    Args:
        team: Team name

    Returns:
        dict structure with 'status' and 'result'
    """
    res = {"status": True, "result": []}
    pool = await get_pool()
    try:
        async with pool.acquire() as conn:
            rows = await conn.fetch(queries["get_sast_stats_by_team"], team)

        if rows:
            for row in rows:
                res["result"].append(
                    {
                        "product": row[0],
                        "total": row[1],
                        "errors": row[2],
                        "warnings": row[3],
                        "info": row[4],
                    }
                )
        logger.debug(f"Got SAST stats for team {team}: {len(res['result'])} products")
    except asyncpg.PostgresError as e:
        logger.error(f"PSQL error in get_sast_stats_by_team: {e}")
        res = {"status": False, "result": str(e)}
    except Exception as e:
        logger.error(f"Error in get_sast_stats_by_team: {e}")
        res = {"status": False, "result": str(e)}
    return res
