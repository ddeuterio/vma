import os
import psycopg2 as psql
from typing import Optional

from loguru import logger
from dotenv import load_dotenv
from psycopg2.extras import execute_values
from datetime import datetime

# TODO: study asyncpg
from psycopg2 import pool

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
            id = %s;
    """,
    "get_nvd_sync_data": """
        SELECT
            id, last_fetched, chcksum
        FROM
            nvd_sync
        WHERE
            id = %s;
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
            vulnerabilities.cve_id,
            vulnerabilities.source_identifier,
            vulnerabilities.published_date,
            vulnerabilities.last_modified,
            vulnerabilities.vuln_status,
            vulnerabilities.refs,
            vulnerabilities.descriptions,
            vulnerabilities.weakness,
            vulnerabilities.configurations,
            cvss_metrics.source,
            cvss_metrics.cvss_version,
            cvss_metrics.vector_string,
            cvss_metrics.base_score,
            cvss_metrics.base_severity
        FROM
            vulnerabilities
        INNER JOIN
            cvss_metrics
        ON
            vulnerabilities.cve_id = cvss_metrics.cve_id
        WHERE
            vulnerabilities.cve_id ILIKE %s
        ORDER BY
            cvss_metrics.base_score DESC
        LIMIT 25;
    """,
    "insert_cve": """
        INSERT INTO vulnerabilities
            (cve_id, source_identifier, published_date, last_modified, vuln_status, refs, descriptions, weakness, configurations)
        VALUES %s
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
        VALUES %s
        ON CONFLICT (cve_id, source, cvss_version)
        DO UPDATE SET
            vector_string = EXCLUDED.vector_string,
            base_score = EXCLUDED.base_score,
            base_severity = EXCLUDED.base_severity;
    """,
    "insert_fetch_date": """
        INSERT INTO nvd_sync
            (id, last_fetched, chcksum)
        VALUES (%s, %s, %s)
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
            team = ANY(%s)
        ORDER BY
            id;
    """,
    "get_product": """
        SELECT
            id, description, team
        FROM
            products
        WHERE
            id = %s AND
            team = ANY(%s)
        ORDER BY
            id;
    """,
    "insert_product": """
        INSERT INTO
            products (id, description, team)
        VALUES
            (%s, %s, %s)
        RETURNING
            id;
    """,
    "delete_product": """
        DELETE FROM
            products
        WHERE
            id = %s AND
            team = %s;
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
            team = ANY(%s)
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
            name = %s AND
            team = ANY(%s)
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
            product = %s AND
            team = ANY(%s)
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
            name = %s AND
            product = %s AND
            team = ANY(%s)
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
            name = %s AND
            version = %s AND
            product = %s AND
            team = ANY(%s)
        ORDER BY
            product,
            name,
            version;
    """,
    "insert_image": """
        INSERT INTO
            images (name, version, product, team)
        VALUES
            (%s, %s, %s, %s)
        RETURNING
            name, version, product, team;
    """,
    "delete_image_by_name": """
        DELETE FROM
            images
        WHERE
            name = %s AND
            product = %s AND
            team = %s;
    """,
    "delete_image_by_name_version": """
        DELETE FROM
            images
        WHERE
            name = %s AND
            version = %s AND
            product = %s AND
            team = %s;
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
            iv.product = %s
            AND iv.image_name = %s
            AND iv.image_version = %s
            AND iv.team = %s
        ORDER BY
            iv.cve,
            iv.affected_component;
    """,
    "insert_image_vulnerabilities": """
        INSERT INTO image_vulnerabilities
            (scanner, image_name, image_version, product, team, cve, fix_versions, first_seen, last_seen, affected_component_type, affected_component, affected_version, affected_path)
        VALUES
            %s
        ON CONFLICT
            (scanner, image_name, image_version, product, team, cve, affected_component_type, affected_component)
        DO UPDATE SET
            last_seen = EXCLUDED.last_seen;
    """,
    "compare_image_versions": """
        WITH image_a AS (
            SELECT DISTINCT
                cve,
                affected_component_type,
                affected_component,
                affected_path
            FROM image_vulnerabilities
            WHERE team = %s
            AND product = %s
            AND image_name = %s
            AND image_version = %s
        ),
        image_b AS (
            SELECT DISTINCT
                cve,
                affected_component_type,
                affected_component,
                affected_path
            FROM image_vulnerabilities
            WHERE team = %s
            AND product = %s
            AND image_name = %s
            AND image_version = %s
        ),
        diff AS (
            SELECT
                COALESCE(a.cve, b.cve) AS cve_id,
                COALESCE(a.affected_component_type, b.affected_component_type) AS component_type,
                COALESCE(a.affected_component, b.affected_component) AS component,
                COALESCE(a.affected_path, b.affected_path) AS component_path,
                CASE
                    WHEN a.cve IS NOT NULL AND b.cve IS NOT NULL THEN 'shared'
                    WHEN a.cve IS NOT NULL THEN 'only_version_a'
                    ELSE 'only_version_b'
                END AS comparison
            FROM image_a a
            FULL OUTER JOIN image_b b USING (cve, affected_component_type, affected_component)
        ),
        cvss AS (
            SELECT
                cve_id,
                source,
                cvss_version,
                vector_string,
                base_score,
                base_severity
            FROM cvss_metrics
        )
        SELECT
            d.cve_id,
            d.component_type,
            d.component,
            d.component_path,
            d.comparison,
            m.base_score,
            m.cvss_version,
            m.base_severity
        FROM diff d
        LEFT JOIN cvss m ON m.cve_id = d.cve_id
        ORDER BY d.cve_id, d.component, d.component_path;
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
            email = %s;
    """,
    "get_users_by_password": """
        SELECT
            email, hpass, name, is_root
        FROM
            users
        WHERE
            email = %s AND
            hpass = %s;
    """,
    "get_users_by_team": """
        SELECT
            email, hpass, name, is_root
        FROM
            users
        WHERE
            team = %s;
    """,
    "insert_users": """
        INSERT INTO
            users (email, hpass, name, is_root)
        VALUES
            (%s, %s, %s, %s)
        RETURNING email;
    """,
    "delete_user_by_email": """
        DELETE FROM
            users
        WHERE
            email = %s;
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
            name = %s;
    """,
    "insert_teams": """
        INSERT INTO
            teams (name, description)
        VALUES
            (%s, %s)
        RETURNING
            name;
    """,
    "delete_teams": """
        DELETE FROM
            teams
        WHERE
            name = %s;
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
            user_email = %s;
    """,
    "insert_user_team_scopes": """
        INSERT INTO user_team_scopes 
            (user_email, team_id, scope)
        VALUES
            (%s, %s, %s)
        ON CONFLICT
            (user_email, team_id)
        DO UPDATE SET
            scope = EXCLUDED.scope;
    """,
    "update_user_team_scopes": """
        UPDATE
            user_team_scopes
        SET
            user_email = %s,
            team_id = %s,
            scope = %
        WHERE
            user_email = %s;
    """,
    "delete_user_team_scopes_by_user": """
        DELETE FROM
            user_team_scopes
        WHERE
            user_email = %s;
    """,
    "insert_api_token": """
        INSERT INTO
            api_tokens (token_hash, prefix, user_email, description, expires_at)
        VALUES
            (%s, %s, %s, %s, %s)
        RETURNING
            id, prefix, created_at;
    """,
    "get_api_token_by_hash": """
        SELECT
            id, token_hash, user_email, revoked, expires_at, last_used_at, description
        FROM
            api_tokens
        WHERE
            token_hash = %s;
    """,
    "get_api_token_by_prefix": """
        SELECT
            id, token_hash, user_email, revoked, expires_at, last_used_at, description
        FROM
            api_tokens
        WHERE
            prefix = %s;
    """,
    "list_api_tokens_by_user": """
        SELECT
            id, prefix, user_email, description, created_at, last_used_at, expires_at, revoked
        FROM
            api_tokens
        WHERE
            user_email = %s AND
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
            id = %s AND
            user_email = %s
        RETURNING id;
    """,
    "revoke_api_token_admin": """
        UPDATE
            api_tokens
        SET
            revoked = TRUE
        WHERE
            id = %s
        RETURNING id;
    """,
    "update_token_last_used": """
        UPDATE
            api_tokens
        SET
            last_used_at = NOW()
        WHERE
            id = %s;
    """,
    "get_api_token_by_id": """
        SELECT
            id, prefix, user_email, description, created_at, last_used_at, expires_at, revoked
        FROM
            api_tokens
        WHERE
            id = %s;
    """,
    "insert_osv_vulnerability": """
        INSERT INTO osv_vulnerabilities
            (osv_id, schema_version, modified, published, withdrawn, summary, details, database_specific)
        VALUES %s
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
        VALUES %s
        ON CONFLICT (osv_id, alias)
        DO NOTHING;
    """,
    "insert_osv_reference": """
        INSERT INTO osv_references
            (osv_id, ref_type, url)
        VALUES %s;
    """,
    "insert_osv_severity": """
        INSERT INTO osv_severity
            (osv_id, severity_type, score)
        VALUES %s;
    """,
    "insert_osv_affected": """
        INSERT INTO osv_affected
            (osv_id, package_ecosystem, package_name, package_purl, ranges, versions, ecosystem_specific, database_specific)
        VALUES %s;
    """,
    "insert_osv_credit": """
        INSERT INTO osv_credits
            (osv_id, name, contact, credit_type)
        VALUES %s;
    """,
    "delete_osv_references": """
        DELETE FROM osv_references WHERE osv_id = %s;
    """,
    "delete_osv_severity": """
        DELETE FROM osv_severity WHERE osv_id = %s;
    """,
    "delete_osv_affected": """
        DELETE FROM osv_affected WHERE osv_id = %s;
    """,
    "delete_osv_credits": """
        DELETE FROM osv_credits WHERE osv_id = %s;
    """,
    "get_osv_by_id": """
        SELECT
            osv_id, schema_version, modified, published, withdrawn, summary, details, database_specific
        FROM
            osv_vulnerabilities
        WHERE
            osv_id = %s;
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
            s.severity_type,
            s.score
        FROM
            osv_vulnerabilities v
        LEFT JOIN
            osv_severity s ON v.osv_id = s.osv_id
        WHERE
            v.osv_id ILIKE %s
        ORDER BY
            v.osv_id DESC
        LIMIT 100;
    """,
    "get_osv_aliases": """
        SELECT
            alias
        FROM
            osv_aliases
        WHERE
            osv_id = %s;
    """,
    "get_osv_by_cve": """
        SELECT
            v.osv_id, v.schema_version, v.modified, v.published, v.withdrawn, v.summary, v.details
        FROM
            osv_vulnerabilities v
        INNER JOIN
            osv_aliases a ON v.osv_id = a.osv_id
        WHERE
            a.alias = %s;
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
            nv.cve_id = %s;
    """,
    "get_combined_vulnerability_data": """
        WITH input_vuln AS (
            -- Determine if input is CVE or OSV ID and get base vulnerability info
            SELECT
                v.cve_id,
                v.source_identifier,
                v.published_date as nvd_published,
                v.last_modified as nvd_modified,
                v.vuln_status,
                v.refs as nvd_refs,
                v.descriptions as nvd_descriptions,
                v.weakness,
                v.configurations,
                oa.osv_id
            FROM vulnerabilities v
            LEFT JOIN osv_aliases oa ON v.cve_id = oa.alias
            WHERE v.cve_id = %s

            UNION

            SELECT
                oa2.alias as cve_id,
                v2.source_identifier,
                v2.published_date as nvd_published,
                v2.last_modified as nvd_modified,
                v2.vuln_status,
                v2.refs as nvd_refs,
                v2.descriptions as nvd_descriptions,
                v2.weakness,
                v2.configurations,
                ov.osv_id
            FROM osv_vulnerabilities ov
            LEFT JOIN osv_aliases oa2 ON ov.osv_id = oa2.osv_id AND oa2.alias LIKE 'CVE-%'
            LEFT JOIN vulnerabilities v2 ON oa2.alias = v2.cve_id
            WHERE ov.osv_id = %s
        ),
        nvd_cvss AS (
            -- Get all CVSS metrics from NVD
            SELECT
                iv.cve_id,
                json_agg(
                    json_build_object(
                        'source', cm.source,
                        'cvss_version', cm.cvss_version,
                        'vector_string', cm.vector_string,
                        'base_score', cm.base_score,
                        'base_severity', cm.base_severity
                    ) ORDER BY cm.base_score DESC
                ) as nvd_cvss_metrics
            FROM input_vuln iv
            LEFT JOIN cvss_metrics cm ON iv.cve_id = cm.cve_id
            WHERE iv.cve_id IS NOT NULL
            GROUP BY iv.cve_id
        ),
        osv_data AS (
            -- Get OSV vulnerability details
            SELECT
                ov.osv_id,
                ov.schema_version,
                ov.modified as osv_modified,
                ov.published as osv_published,
                ov.withdrawn,
                ov.summary as osv_summary,
                ov.details as osv_details,
                ov.database_specific as osv_database_specific
            FROM input_vuln iv
            JOIN osv_vulnerabilities ov ON iv.osv_id = ov.osv_id
            WHERE iv.osv_id IS NOT NULL
        ),
        osv_aliases_agg AS (
            -- Get all OSV aliases
            SELECT
                od.osv_id,
                json_agg(oa.alias) as osv_aliases
            FROM osv_data od
            LEFT JOIN osv_aliases oa ON od.osv_id = oa.osv_id
            GROUP BY od.osv_id
        ),
        osv_severity_agg AS (
            -- Get OSV severity data
            SELECT
                od.osv_id,
                json_agg(
                    json_build_object(
                        'type', os.severity_type,
                        'score', os.score
                    )
                ) as osv_severity
            FROM osv_data od
            LEFT JOIN osv_severity os ON od.osv_id = os.osv_id
            GROUP BY od.osv_id
        ),
        osv_refs_agg AS (
            -- Get OSV references
            SELECT
                od.osv_id,
                json_agg(
                    json_build_object(
                        'type', oref.ref_type,
                        'url', oref.url
                    )
                ) as osv_references
            FROM osv_data od
            LEFT JOIN osv_references oref ON od.osv_id = oref.osv_id
            GROUP BY od.osv_id
        ),
        osv_affected_agg AS (
            -- Get OSV affected packages
            SELECT
                od.osv_id,
                json_agg(
                    json_build_object(
                        'ecosystem', oaf.package_ecosystem,
                        'package', oaf.package_name,
                        'purl', oaf.package_purl,
                        'ranges', oaf.ranges,
                        'versions', oaf.versions,
                        'ecosystem_specific', oaf.ecosystem_specific,
                        'database_specific', oaf.database_specific
                    )
                ) as osv_affected
            FROM osv_data od
            LEFT JOIN osv_affected oaf ON od.osv_id = oaf.osv_id
            GROUP BY od.osv_id
        ),
        osv_credits_agg AS (
            -- Get OSV credits
            SELECT
                od.osv_id,
                json_agg(
                    json_build_object(
                        'name', oc.name,
                        'contact', oc.contact,
                        'type', oc.credit_type
                    )
                ) as osv_credits
            FROM osv_data od
            LEFT JOIN osv_credits oc ON od.osv_id = oc.osv_id
            GROUP BY od.osv_id
        )
        -- Final combined result
        SELECT
            iv.cve_id,
            iv.source_identifier,
            iv.nvd_published,
            iv.nvd_modified,
            iv.vuln_status,
            iv.nvd_refs,
            iv.nvd_descriptions,
            iv.weakness,
            iv.configurations,
            nc.nvd_cvss_metrics,
            od.osv_id,
            od.schema_version,
            od.osv_published,
            od.osv_modified,
            od.withdrawn,
            od.osv_summary,
            od.osv_details,
            od.osv_database_specific,
            oaa.osv_aliases,
            osa.osv_severity,
            ora.osv_references,
            oafa.osv_affected,
            oca.osv_credits,
            CASE
                WHEN iv.cve_id IS NOT NULL AND od.osv_id IS NOT NULL THEN 'both'
                WHEN iv.cve_id IS NOT NULL THEN 'nvd_only'
                WHEN od.osv_id IS NOT NULL THEN 'osv_only'
                ELSE 'none'
            END as data_source
        FROM input_vuln iv
        LEFT JOIN nvd_cvss nc ON iv.cve_id = nc.cve_id
        LEFT JOIN osv_data od ON iv.osv_id = od.osv_id
        LEFT JOIN osv_aliases_agg oaa ON od.osv_id = oaa.osv_id
        LEFT JOIN osv_severity_agg osa ON od.osv_id = osa.osv_id
        LEFT JOIN osv_refs_agg ora ON od.osv_id = ora.osv_id
        LEFT JOIN osv_affected_agg oafa ON od.osv_id = oafa.osv_id
        LEFT JOIN osv_credits_agg oca ON od.osv_id = oca.osv_id
        LIMIT 1;
    """,
}

_conn_pool = None


def get_conn():
    global _conn_pool
    if _conn_pool is None:
        _conn_pool = pool.SimpleConnectionPool(
            minconn=_min_conn,
            maxconn=_max_conn,
            host=_db_host,
            dbname=_db_name,
            user=_db_user,
            password=_db_pass,
        )
    return _conn_pool.getconn()


def put_conn(conn, close=False):
    if _conn_pool is not None:
        _conn_pool.putconn(conn, close=close)


def get_all_years_nvd_sync() -> list | None:
    """
    Gets the date (extended ISO-8601 date/time format) of the last time that the database was updated for all years.

    Returns:
        Date of the last time that the vulnerabilities where updated
    """
    dt = None
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(queries["get_nvd_sync_data"])
            dt = cur.fetchall()
            logger.debug("All years gotten from the nvd_sync table")
    except psql.Error as e:
        logger.error(f"PSQL error: {e}")
    except Exception as e:
        logger.error(f"DB error: {e}")
    finally:
        put_conn(conn)

    res = [i[0] for i in dt] if dt else None
    return res


def get_nvd_sync_data(year) -> tuple | None:
    """
    Gets the date (extended ISO-8601 date/time format) of the last time that the database was updated.

    Returns:
        Date of the last time that the vulnerabilities where updated
    """
    dt = None
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(queries["get_nvd_sync_data"], year)
            dt = cur.fetchone()
            logger.debug(f"Last date when {year} CVE data was updated was {dt}")
    except psql.Error as e:
        logger.error(f"PSQL error: {e}")
    except Exception as e:
        logger.error(f"DB error: {e}")
    finally:
        put_conn(conn)
    return dt


def get_last_fetched_date(year) -> datetime | None:
    """
    Gets the date (extended ISO-8601 date/time format) of the last time that the database was updated.

    Args:
        year: Year identifier or 'recent' for recent updates

    Returns:
        datetime object of last fetch, or None if no sync record exists
    """
    dt = None
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(queries["get_fetch_date"], (year,))
            dt = cur.fetchone()
            if dt:
                logger.debug(f"Last date when CVE data was updated was {dt[0]}")
            else:
                logger.debug("Couldn't fecth the update date")
    except psql.Error as e:
        logger.error(f"PSQL error: {e}")
    except Exception as e:
        logger.error(f"DB error: {e}")
    finally:
        put_conn(conn)

    res = datetime.fromisoformat(dt[0]).astimezone() if dt else None
    return res


def insert_year_data(value) -> bool:
    """
    Update the date of the last fetched value (extended ISO-8601 date/time format)

    Args:
        value gotten from the last recent file
    Returns:
        Boolean with the result of the query
    """
    res = True
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(queries["insert_fetch_date"], value)
            conn.commit()
            logger.debug(f"Last fetched date was updated to {str(value)}")
    except psql.Error as e:
        logger.error(f"PSQL error: {e}")
        res = False
    except Exception as e:
        logger.error(f"DB error: {e}")
        res = False
    finally:
        put_conn(conn)
    return res


def insert_vulnerabilities(data_cve: list, data_cvss: list) -> dict:
    """
    Inserts bulk data into the DB

    Args:
        NVD json data parsed using function nvd.parse_nvd_data() for CVE and CVSS

    Returns:
        dict structure with 'status' and 'result'
    """
    res = True
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            execute_values(cur, queries["insert_cve"], data_cve, page_size=_page_size)
            conn.commit()
            execute_values(cur, queries["insert_cvss"], data_cvss, page_size=_page_size)
            conn.commit()
    except psql.Error as e:
        logger.error(f"PSQL error: {e}")
        res = False
    except Exception as e:
        logger.error(f"DB error: {e}")
        res = False
    finally:
        put_conn(conn)
    return {"status": res, "result": {"num_cve": len(data_cve)}}


def get_vulnerabilities_by_id(id: str) -> dict:
    """
    Get the vulnerabilities based on the cve id pattern

    Args:
        id: cve id pattern

    Returns:
        dict structure with 'status' and 'result'
    """
    res = {"status": True, "result": {}}
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(queries["get_cves"], (id,))
            aux = cur.fetchall()

        logger.debug(
            f"A total of {len(aux)} vulnerabilities have been found for the filter {id}"
        )

        for vuln in aux:
            cve_id = vuln[0]
            source_identifier = vuln[1]
            published_date = str(vuln[2])
            last_modified = str(vuln[3])
            status = vuln[4]
            refs = vuln[5]
            descriptions = vuln[6]
            weakness = vuln[7]
            configs = vuln[8]
            cvss_source = vuln[9]
            cvss_version = vuln[10]
            cvss_vs = vuln[11]
            cvss_bscore = vuln[12]
            cvss_bsev = vuln[13]

            if cve_id not in res["result"]:
                res["result"][cve_id] = {
                    "source": source_identifier,
                    "published_date": published_date,
                    "last_modified": last_modified,
                    "status": status,
                    "references": refs,
                    "descriptions": descriptions,
                    "weakness": weakness,
                    "configurations": configs,
                    "cvss": {},
                }

            if cvss_version not in res["result"][cve_id]["cvss"]:
                res["result"][cve_id]["cvss"][cvss_version] = []
            res["result"][cve_id]["cvss"][cvss_version].append(
                {
                    "source": cvss_source,
                    "vector_string": cvss_vs,
                    "base_score": cvss_bscore,
                    "base_severity": cvss_bsev,
                }
            )
        if not res["result"]:
            res["status"] = False
    except psql.Error as e:
        logger.error(f"PSQL error: {e}")
        res = {"status": False, "result": None}
    except Exception as e:
        logger.error(f"DB error: {e}")
        res = {"status": False, "result": None}
    finally:
        put_conn(conn)
    return res


def get_products(teams: list, id: Optional[str] = None) -> dict:
    """
    Retrieve products.

    Args:
        list of teams (scope)
        id of the product
    Returns:
        dict structure with 'status' and 'result'
    """
    res = {"status": True, "result": []}
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            if id:
                cur.execute(queries["get_product"], (id, teams))
            else:
                cur.execute(queries["get_products"], (teams,))
            q = cur.fetchall()

        if not q:
            res["status"] = False
        else:
            for p in q:
                res["result"].append({"id": p[0], "description": p[1], "team": p[2]})
    except psql.Error as e:
        logger.error(f"PSQL error: {e}")
        res = {"status": False, "result": None}
    except Exception as e:
        logger.error(f"DB error: {e}")
        res = {"status": False, "result": None}
    finally:
        put_conn(conn)
    return res


def insert_product(name: str, description: str, team: str) -> dict:
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
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(queries["insert_product"], (name, description, team))
            q = cur.fetchone()
            conn.commit()

        if q:
            res["result"] = {"id": q[0]}
            logger.debug(f"New product with name {q[0]} was created")
        else:
            res["status"] = False
            logger.debug("Failed creating the product")
    except psql.Error as e:
        logger.error(f"PSQL error: {e}")
        res = {"status": False, "result": None}
    except Exception as e:
        logger.error(f"DB error: {e}")
        res = {"status": False, "result": None}
    finally:
        put_conn(conn)
    return res


def delete_product(id: str, team: str) -> dict:
    """
    Delete a product

    Args:
        product id
        team

    Returns:
        dict structure with 'status' and 'result'
    """
    res = {"status": True, "result": None}
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(queries["delete_product"], (id, team))
            if not cur.rowcount:
                res["status"] = False
            else:
                res["result"] = {"deleted_rows": cur.rowcount}
    except psql.Error as e:
        logger.error(f"PSQL error: {e}")
        res = {"status": False, "result": None}
    except Exception as e:
        logger.error(f"DB error: {e}")
        res = {"status": False, "result": None}
    finally:
        put_conn(conn)
    return res


def get_images(
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
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            if product and name and version:
                cur.execute(
                    queries["get_images_by_name_version_product"],
                    (name, version, product, teams),
                )
            elif product and name:
                cur.execute(
                    queries["get_images_by_name_product"], (name, product, teams)
                )
            elif product:
                cur.execute(queries["get_images_by_product"], (product, teams))
            else:
                cur.execute(queries["get_images"], (teams,))
            q = cur.fetchall()

        if not q:
            logger.debug("No images were found")
        else:
            logger.debug("A total of {len(q)} images were found")
            for im in q:
                res["result"].append(
                    {
                        "name": im[0],
                        "version": im[1],
                        "product": im[2],
                        "team": im[3],
                    }
                )
    except psql.Error as e:
        logger.error(f"PSQL error: {e}")
        res = {"status": False, "result": None}
    except Exception as e:
        logger.error(f"DB error: {e}")
        res = {"status": False, "result": None}
    finally:
        put_conn(conn)
    return res


def insert_image(name: str, version: str, product: str, team: str) -> dict:
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
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(queries["insert_image"], (name, version, product, team))
            q = cur.fetchone()
            conn.commit()

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
    except psql.Error as e:
        logger.error(f"PSQL error: {e}")
        res = {"status": False, "result": None}
    except Exception as e:
        logger.error(f"DB error: {e}")
        res = {"status": False, "result": None}
    finally:
        put_conn(conn)
    return res


def get_image_vulnerabilities(product: str, name: str, version: str, team: str) -> dict:
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
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                queries["get_image_vulnerabilities"], (product, name, version, team)
            )
            q = cur.fetchall()

        res["result"] = q
        logger.debug(
            f"A total of {len(q)} vulns for image {team}/{product} {name}:{version}"
        )
    except psql.Error as e:
        logger.error(f"PSQL error: {e}")
        res = {"status": False, "result": None}
    except Exception as e:
        logger.error(f"DB error: {e}")
        res = {"status": False, "result": None}
    finally:
        put_conn(conn)
    return res


def insert_image_vulnerabilities(values: list) -> dict:
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
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            execute_values(
                cur,
                queries["insert_image_vulnerabilities"],
                values,
                page_size=_page_size,
            )
            conn.commit()

        logger.debug(f"A total of {len(values)} have been inserted")
        res = {"status": True, "result": {"num_cve": len(values)}}
    except psql.Error as e:
        logger.error(f"PSQL error: {e}")
        res = {"status": False, "result": None}
    except Exception as e:
        logger.error(f"DB error: {e}")
        res = {"status": False, "result": None}
    finally:
        put_conn(conn)
    return res


def compare_image_versions(
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
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                queries["compare_image_versions"],
                (team, product, image, version_a, product, image, version_b),
            )
            q = cur.fetchall()

        if not q:
            res["status"] = False
        else:
            res["result"] = q
        logger.debug("Data from the two versions gotten")
    except psql.Error as e:
        logger.error(f"PSQL error: {e}")
        res = {"status": False, "result": None}
    except Exception as e:
        logger.error(f"DB error: {e}")
        res = {"status": False, "result": None}
    finally:
        put_conn(conn)
    return res


def delete_image(team, product, name=None, version=None) -> dict:
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
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            if version and name:
                cur.execute(
                    queries["delete_image_by_name_version"],
                    (name, version, product, team),
                )
            elif name:
                cur.execute(queries["delete_image_by_name"], (name, product, team))
            if not cur.rowcount:
                logger.error(
                    f"Image could not be deleted properly {name} {product} {team}"
                )
                res["status"] = False
            else:
                logger.debug(f"Image was deleted properly {name} {product} {team}")
                res["result"] = {"deleted_rows": cur.rowcount}
    except psql.Error as e:
        logger.error(f"PSQL error: {e}")
        res = {"status": False, "result": None}
    except Exception as e:
        logger.error(f"DB error: {e}")
        res = {"status": False, "result": None}
    finally:
        put_conn(conn)
    return res


def get_users(email=None) -> dict:
    """
    Retrieve users.

    Args:
        email
    Returns:
        dict structure with 'status' and 'result'
    """
    res = {"status": True, "result": []}
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            if email:
                cur.execute(queries["get_users_by_email"], (email,))
            else:
                cur.execute(queries["get_users"])
            q = cur.fetchall()
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
                    cur.execute(queries["get_user_team_scopes_by_email"], (email,))
                else:
                    cur.execute(queries["get_user_team_scopes"])
                q = cur.fetchall()
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
    except psql.Error as e:
        logger.error(f"PSQL error: {e}")
        res = {"status": False, "result": None}
    except Exception as e:
        logger.error(f"DB error: {e}")
        res = {"status": False, "result": None}
    finally:
        put_conn(conn)
    return res


def get_users_w_hpass(email) -> dict:
    """
    Retrieve users.

    Args:
        email
    Returns:
        dict structure with 'status' and 'result'
    """
    res = {"status": True, "result": []}
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(queries["get_users_by_email"], (email,))
            q = cur.fetchall()
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
                cur.execute(queries["get_user_team_scopes_by_email"], (email,))
                q = cur.fetchall()
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
    except psql.Error as e:
        logger.error(f"PSQL error: {e}")
        res = {"status": False, "result": None}
    except Exception as e:
        logger.error(f"DB error: {e}")
        res = {"status": False, "result": None}
    finally:
        put_conn(conn)
    return res


def insert_users(email, password, name, scopes, is_root=False) -> dict:
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
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(queries["insert_users"], (email, password, name, is_root))
            for t, s in scopes.items():
                cur.execute(queries["insert_user_team_scopes"], (email, t, s))
            conn.commit()

        logger.debug(f"A new user {email} has been added")
        res = {"status": True, "result": {"user": email}}
    except psql.Error as e:
        logger.error(f"PSQL error: {e}")
        res = {"status": False, "result": None}
    except Exception as e:
        logger.error(f"DB error: {e}")
        res = {"status": False, "result": None}
    finally:
        put_conn(conn)
    return res


def update_users(email, password=None, name=None, scopes=None, is_root=None) -> dict:
    """
    Update an user

    Args:
        email
        name
        password
        scopes: dict with team-scope bindings
    Returns:
        dict structure with 'status' and 'result'
    """
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            res = get_users(email)
            original_email = res["result"][0]["email"] if res["status"] else ""
            logger.debug(f"original email is {original_email}")
            update_fields = []
            fields = []

            if original_email != email:
                update_fields.append("email = %s")
                fields.append(email)

            if password:
                update_fields.append("hpass = %s")
                fields.append(password)

            if name:
                update_fields.append("name = %s")
                fields.append(name)

            if is_root is not None:
                update_fields.append("is_root = %s")
                fields.append(is_root)

            if update_fields:
                fields.append(email)
                q = f"""
                    UPDATE users SET {(", ").join(update_fields)} WHERE email = %s;
                """
                cur.execute(q, tuple(fields))

            if scopes:
                logger.debug("updating scopes")
                for t, s in scopes.items():
                    logger.debug(f"team: {t}; scope: {s}")
                    cur.execute(queries["insert_user_team_scopes"], (email, t, s))
            conn.commit()
        logger.debug(f"A user {email} has been updated")
    except psql.Error as e:
        logger.error(f"PSQL error: {e}")
        res = {"status": False, "result": None}
    except Exception as e:
        logger.error(f"DB error: {e}")
        res = {"status": False, "result": None}
    finally:
        put_conn(conn)
    return {"status": True, "result": {"user": email}}


def delete_user(email) -> dict:
    """
    Deletes user

    Args:
        email: id

    Returns:
        dict structure with 'status' and 'result'
    """
    res = {"status": True, "result": None}
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(queries["delete_user_by_email"], (email))
            if not cur.rowcount:
                res["status"] = False
            else:
                res["result"] = {"deleted_rows": cur.rowcount}
    except psql.Error as e:
        logger.error(f"PSQL error: {e}")
        res = {"status": False, "result": None}
    except Exception as e:
        logger.error(f"DB error: {e}")
        res = {"status": False, "result": None}
    finally:
        put_conn(conn)
    return res


def get_teams(name=None) -> dict:
    """
    Retrieve teams.

    Args:
        name
    Returns:
        dict structure with 'status' and 'result'
    """
    res = {"status": True, "result": []}
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            if name:
                cur.execute(queries["get_teams_by_name"], (name,))
            else:
                cur.execute(queries["get_teams"])
            q = cur.fetchall()

        if not q:
            logger.debug("No teams where identified")
        else:
            logger.debug(f"A total of {len(q)} teams were identified")
            for t in q:
                res["result"].append({"name": t[0], "description": t[1]})
    except psql.Error as e:
        logger.error(f"PSQL error: {e}")
        res = {"status": False, "result": None}
    except Exception as e:
        logger.error(f"DB error: {e}")
        res = {"status": False, "result": None}
    finally:
        put_conn(conn)
    return res


def insert_teams(name: str, description: str = "") -> dict:
    """
    Insert a team

    Args:
        name
        description
    Returns:
        dict structure with 'status' and 'result'
    """
    res = {"status": True, "result": None}
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(queries["insert_teams"], (name, description))
            conn.commit()
            q = cur.fetchone()

        if q:
            res["result"] = {}
            res["result"]["name"] = q[0]
            logger.debug(f"A new team with name {q} has been added")
        else:
            logger.debug("Failed adding the team")
    except psql.Error as e:
        logger.error(f"PSQL error: {e}")
        res["result"] = False
    except Exception as e:
        logger.error(f"DB error: {e}")
        res["result"] = False
    finally:
        put_conn(conn)
    return res


def delete_team(id) -> dict:
    """
    Deletes a team

    Args:
        id

    Returns:
        dict structure with 'status' and 'result'
    """
    res = {"status": True, "result": None}
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(queries["delete_teams"], (id,))
            if not cur.rowcount:
                logger.error(f"Team with id {id} could not be removed")
                res["status"] = False
            else:
                logger.debug(f"Team with id {id} was removed")
                res["result"] = {"deleted_rows": cur.rowcount}
    except psql.Error as e:
        logger.error(f"PSQL error: {e}")
        res = {"status": False, "result": None}
    except Exception as e:
        logger.error(f"DB error: {e}")
        res = {"status": False, "result": None}
    finally:
        put_conn(conn)
    return res


def get_scope_by_user(email=None) -> dict:
    conn = get_conn()
    res = {"status": True, "result": None}
    try:
        with conn.cursor() as cur:
            if email:
                cur.execute(queries["get_user_team_scopes_by_email"], (email,))
            else:
                cur.execute(queries["get_user_team_scopes"])

            if not cur.rowcount:
                logger.error("Scopes for users could not be identified")
                res["status"] = False
            else:
                q = cur.fetchall()
                if not q:
                    logger.error("Scopes for users could not be identified")
                    res["status"] = False
                else:
                    logger.debug("Scopes for users were identified")
                    res["result"] = {}
                    for r in q:
                        res["result"][r[1]] = r[2]
    except psql.Error as e:
        logger.error(f"PSQL error: {e}")
        res = {"status": False, "result": None}
    except Exception as e:
        logger.error(f"DB error: {e}")
        res = {"status": False, "result": None}
    finally:
        put_conn(conn)
    return res


def insert_api_token(
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
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                queries["insert_api_token"],
                (token_hash, prefix, user_email, description, expires_at),
            )
            q = cur.fetchone()
            conn.commit()

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
    finally:
        put_conn(conn)
    return res


def get_api_token_by_hash(token_hash: str) -> dict:
    """
    Get API token by hash for validation.

    Args:
        token_hash: Hash of the token

    Returns:
        dict: {"status": bool, "result": token_data or error}
    """
    res = {"status": False, "result": None}
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(queries["get_api_token_by_hash"], (token_hash,))
            q = cur.fetchone()

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
    finally:
        put_conn(conn)
    return res


def get_api_token_by_prefix(prefix: str) -> dict:
    """
    Get API token by prefix for validation.

    Args:
        prefix: First 12 characters of the token

    Returns:
        dict: {"status": bool, "result": token_data or error}
    """
    res = {"status": False, "result": None}
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(queries["get_api_token_by_prefix"], (prefix,))
            q = cur.fetchone()

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
    finally:
        put_conn(conn)
    return res


def get_api_token_by_id(token_id: int) -> dict:
    """Get API token by ID."""
    res = {"status": False, "result": None}
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(queries["get_api_token_by_id"], (token_id,))
            q = cur.fetchone()

        if not q:
            logger.debug("Token not found")
            res["result"] = "Token not found"
            res["status"] = True
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
    finally:
        put_conn(conn)
    return res


def list_api_tokens(user_email: Optional[str] = None) -> dict:
    """
    List API tokens.

    Args:
        user_email: Filter by user (None for all users)

    Returns:
        dict: {"status": bool, "result": list of tokens or error}
    """
    res = {"status": False, "result": None}
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            if not user_email:
                cur.execute(queries["list_all_api_tokens"])
            else:
                cur.execute(queries["list_api_tokens_by_user"], (user_email,))

            q = cur.fetchall()

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
            res["result"] = "No tokens to display"
    except Exception as e:
        logger.error(f"Error getting API token: {e}")
        res["result"] = "Could not fetch tokens"
    finally:
        put_conn(conn)
    return res


def revoke_api_token(
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
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            if admin:
                cur.execute(queries["revoke_api_token_admin"], (token_id,))
            else:
                cur.execute(queries["revoke_api_token"], (token_id, user_email))

            q = cur.fetchone()
            conn.commit()

        if not q:
            logger.error("Token could not be revoked")
            res["result"] = "Token could not be revoked"
            return res

        res["status"] = True
        res["result"] = "Token revoked successfully"
    except Exception as e:
        logger.error(f"Error getting API token: {e}")
        res["result"] = str(e)
    finally:
        put_conn(conn)
    return res


def update_token_last_used(token_id: int) -> dict:
    """
    Update last_used_at timestamp for a token.

    Args:
        token_id: ID of token to update

    Returns:
        dict: {"status": bool}
    """
    res = {"status": False, "result": None}
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(queries["update_token_last_used"], (token_id,))
            conn.commit()

        res["status"] = True
        res["result"] = "Token updated successfully"
    except Exception as e:
        logger.error(f"Error getting API token: {e}")
        res["result"] = str(e)
    finally:
        put_conn(conn)
    return res


def insert_osv_data(
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
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            # Insert main vulnerability record
            if data_vuln:
                execute_values(cur, queries["insert_osv_vulnerability"], data_vuln)
                conn.commit()

            # Insert aliases (including CVE mappings for NVD correlation)
            if data_aliases:
                execute_values(cur, queries["insert_osv_alias"], data_aliases)
                conn.commit()

            # For updates, delete existing child records and re-insert
            # This ensures data consistency when OSV entries are updated
            if osv_id:
                cur.execute(queries["delete_osv_references"], (osv_id,))
                cur.execute(queries["delete_osv_severity"], (osv_id,))
                cur.execute(queries["delete_osv_affected"], (osv_id,))
                cur.execute(queries["delete_osv_credits"], (osv_id,))
                conn.commit()

            # Insert child records
            if data_refs:
                execute_values(cur, queries["insert_osv_reference"], data_refs)
                conn.commit()

            if data_severity:
                execute_values(cur, queries["insert_osv_severity"], data_severity)
                conn.commit()

            if data_affected:
                execute_values(cur, queries["insert_osv_affected"], data_affected)
                conn.commit()

            if data_credits:
                execute_values(cur, queries["insert_osv_credit"], data_credits)
                conn.commit()

            logger.info(
                f"Inserted OSV {osv_id}: {len(data_aliases)} aliases, {len(data_refs)} refs, "
                f"{len(data_severity)} severity, {len(data_affected)} affected, {len(data_credits)} credits"
            )
    except psql.Error as e:
        logger.error(f"PSQL error inserting OSV data: {e}")
        res = False
    except Exception as e:
        logger.error(f"Error inserting OSV data: {e}")
        res = False
    finally:
        put_conn(conn)
    return {"status": res, "result": {"osv_id": osv_id}}


def get_osv_by_id(osv_id: str) -> dict:
    """
    Get OSV vulnerability by OSV ID.

    Args:
        osv_id: The OSV identifier (e.g., "OSV-2024-001", "GHSA-xxxx-yyyy-zzzz")

    Returns:
        dict structure with 'status' and 'result'
        result contains: {osv_id, schema_version, modified, published, withdrawn, summary, details, database_specific}
    """
    res = {"status": False, "result": None}
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(queries["get_osv_by_id"], (osv_id,))
            q = cur.fetchone()

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
    except psql.Error as e:
        logger.error(f"PSQL error getting OSV: {e}")
        res["status"] = False
    except Exception as e:
        logger.error(f"Error getting OSV: {e}")
        res["status"] = False
    finally:
        put_conn(conn)
    return res


def get_osv_by_ilike_id(osv_id: str) -> dict:
    """
    Get OSV vulnerability by OSV ID with severity data.

    Args:
        osv_id: The OSV identifier (e.g., "OSV-2024-001", "GHSA-xxxx-yyyy-zzzz")

    Returns:
        dict structure with 'status' and 'result'
        result contains array of: {osv_id, schema_version, modified, published, withdrawn, summary, details, database_specific, severity}
    """
    res = {"status": False, "result": None}
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(queries["get_osvs"], (osv_id,))
            rows = cur.fetchall()

        if not rows:
            logger.debug(f"OSV {osv_id} not found in database")
            res["status"] = False
            res["result"] = None
        else:
            res["status"] = True
            res["result"] = []

            # Group rows by osv_id to aggregate severity data
            osv_dict = {}
            for row in rows:
                current_osv_id = row[0]
                severity_type = row[8]  # severity_type from LEFT JOIN
                severity_score = row[9]  # score from LEFT JOIN

                # Initialize OSV entry if not exists
                if current_osv_id not in osv_dict:
                    osv_dict[current_osv_id] = {
                        "osv_id": current_osv_id,
                        "schema_version": row[1],
                        "modified": row[2],
                        "published": row[3],
                        "withdrawn": row[4],
                        "summary": row[5],
                        "details": row[6],
                        "database_specific": row[7],
                        "severity": {}
                    }

                # Add severity data if present (LEFT JOIN may return NULL)
                if severity_type and severity_score:
                    if severity_type not in osv_dict[current_osv_id]["severity"]:
                        osv_dict[current_osv_id]["severity"][severity_type] = []
                    osv_dict[current_osv_id]["severity"][severity_type].append({
                        "score": severity_score
                    })

            # Convert dict to list (limit to 25 unique OSVs)
            res["result"] = list(osv_dict.values())[:25]
            logger.debug(f"Found {len(res['result'])} OSV results for {osv_id}")
    except psql.Error as e:
        logger.error(f"PSQL error getting OSV: {e}")
        res["status"] = False
    except Exception as e:
        logger.error(f"Error getting OSV: {e}")
        res["status"] = False
    finally:
        put_conn(conn)
    return res


def get_combined_vulnerability_data(vuln_id: str) -> dict:
    """
    Get combined vulnerability data from both NVD and OSV sources.

    This function accepts either a CVE ID (e.g., CVE-2024-1234) or an OSV ID
    (e.g., GHSA-xxxx-yyyy-zzzz, PYSEC-2024-123) and returns comprehensive
    data from both sources when available.

    Args:
        vuln_id: Vulnerability identifier (CVE ID or OSV ID)

    Returns:
        dict structure with 'status' and 'result' containing:
            - NVD data: cve_id, descriptions, CVSS metrics, weakness, configurations
            - OSV data: osv_id, summary, details, severity, affected packages, references
            - data_source: 'both', 'nvd_only', 'osv_only', or 'none'

    Example:
        >>> result = get_combined_vulnerability_data('CVE-2024-1234')
        >>> if result['status']:
        >>>     vuln = result['result']
        >>>     print(f"CVE: {vuln['cve_id']}, OSV: {vuln['osv_id']}")
        >>>     print(f"Data sources: {vuln['data_source']}")
    """
    res = {"status": True, "result": None}
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            # Pass the ID twice - once for CVE lookup, once for OSV lookup
            # The query's UNION will handle determining which one matches
            cur.execute(queries["get_combined_vulnerability_data"], (vuln_id, vuln_id))
            row = cur.fetchone()

        if not row:
            logger.warning(f"No vulnerability data found for ID: {vuln_id}")
            res["status"] = False
            res["result"] = {"error": f"No data found for {vuln_id}"}
            return res

        # Parse the result row
        result = {
            # NVD data
            "cve_id": row[0],
            "source_identifier": row[1],
            "nvd_published": str(row[2]) if row[2] else None,
            "nvd_modified": str(row[3]) if row[3] else None,
            "vuln_status": row[4],
            "nvd_refs": row[5],
            "nvd_descriptions": row[6],
            "weakness": row[7],
            "configurations": row[8],
            "nvd_cvss_metrics": row[9],  # Already JSON aggregated

            # OSV data
            "osv_id": row[10],
            "schema_version": row[11],
            "osv_published": str(row[12]) if row[12] else None,
            "osv_modified": str(row[13]) if row[13] else None,
            "withdrawn": str(row[14]) if row[14] else None,
            "osv_summary": row[15],
            "osv_details": row[16],
            "osv_database_specific": row[17],
            "osv_aliases": row[18],  # Already JSON aggregated
            "osv_severity": row[19],  # Already JSON aggregated
            "osv_references": row[20],  # Already JSON aggregated
            "osv_affected": row[21],  # Already JSON aggregated
            "osv_credits": row[22],  # Already JSON aggregated

            # Metadata
            "data_source": row[23]  # 'both', 'nvd_only', 'osv_only', or 'none'
        }

        res["result"] = result
        logger.debug(
            f"Combined vulnerability data retrieved for {vuln_id}: "
            f"CVE={result['cve_id']}, OSV={result['osv_id']}, "
            f"source={result['data_source']}"
        )

    except psql.Error as e:
        logger.error(f"PSQL error getting combined vulnerability data: {e}")
        res["status"] = False
        res["result"] = {"error": str(e)}
    except Exception as e:
        logger.error(f"Error getting combined vulnerability data: {e}")
        res["status"] = False
        res["result"] = {"error": str(e)}
    finally:
        put_conn(conn)

    return res
