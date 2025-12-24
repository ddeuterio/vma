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
}

conn_pool = pool.SimpleConnectionPool(
    minconn=_min_conn,
    maxconn=_max_conn,
    host=_db_host,
    dbname=_db_name,
    user=_db_user,
    password=_db_pass,
)


def get_all_years_nvd_sync() -> list | None:
    """
    Gets the date (extended ISO-8601 date/time format) of the last time that the database was updated for all years.

    Returns:
        Date of the last time that the vulnerabilities where updated
    """
    dt = None
    conn = conn_pool.getconn()
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
        conn_pool.putconn(conn)

    res = [i[0] for i in dt] if dt else None
    return res


def get_nvd_sync_data(year) -> tuple | None:
    """
    Gets the date (extended ISO-8601 date/time format) of the last time that the database was updated.

    Returns:
        Date of the last time that the vulnerabilities where updated
    """
    dt = None
    conn = conn_pool.getconn()
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
        conn_pool.putconn(conn)
    return dt


def get_last_fetched_date(year) -> dict:
    """
    Gets the date (extended ISO-8601 date/time format) of the last time that the database was updated.

    Returns:
        Date of the last time that the vulnerabilities where updated
    """
    dt = None
    conn = conn_pool.getconn()
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
        conn_pool.putconn(conn)

    res = datetime.fromisoformat(dt[0]).astimezone() if dt else None
    return res


def insert_year_data(value) -> dict:
    """
    Update the date of the last fetched value (extended ISO-8601 date/time format)

    Args:
        value gotten from the last recent file
    Returns:
        Boolean with the result of the query
    """
    res = True
    conn = conn_pool.getconn()
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
        conn_pool.putconn(conn)
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
    conn = conn_pool.getconn()
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
        conn_pool.putconn(conn)
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
    conn = conn_pool.getconn()
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
        conn_pool.putconn(conn)
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
    conn = conn_pool.getconn()
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
        conn_pool.putconn(conn)
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
    conn = conn_pool.getconn()
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
        conn_pool.putconn(conn)
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
    conn = conn_pool.getconn()
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
        conn_pool.putconn(conn)
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
    conn = conn_pool.getconn()
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
        conn_pool.putconn(conn)
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
    conn = conn_pool.getconn()
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
        conn_pool.putconn(conn)
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
    conn = conn_pool.getconn()
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
        conn_pool.putconn(conn)
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
    conn = conn_pool.getconn()
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
        conn_pool.putconn(conn)
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
    conn = conn_pool.getconn()
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
        conn_pool.putconn(conn)
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
    conn = conn_pool.getconn()
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
        conn_pool.putconn(conn)
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
    conn = conn_pool.getconn()
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
        conn_pool.putconn(conn)
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
    conn = conn_pool.getconn()
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
        conn_pool.putconn(conn)
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
    conn = conn_pool.getconn()
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
        conn_pool.putconn(conn)
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
    conn = conn_pool.getconn()
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
        conn_pool.putconn(conn)
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
    conn = conn_pool.getconn()
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
        conn_pool.putconn(conn)
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
    conn = conn_pool.getconn()
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
        conn_pool.putconn(conn)
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
    conn = conn_pool.getconn()
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
        conn_pool.putconn(conn)
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
    conn = conn_pool.getconn()
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
        conn_pool.putconn(conn)
    return res


def get_scope_by_user(email=None) -> dict:
    conn = conn_pool.getconn()
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
        conn_pool.putconn(conn)
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
    conn = conn_pool.getconn()
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
        conn_pool.putconn(conn)
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
    conn = conn_pool.getconn()
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
        conn_pool.putconn(conn)
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
    conn = conn_pool.getconn()
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
        conn_pool.putconn(conn)
    return res


def get_api_token_by_id(token_id: int) -> dict:
    """Get API token by ID."""
    res = {"status": False, "result": None}
    conn = conn_pool.getconn()
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
        conn_pool.putconn(conn)
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
    conn = conn_pool.getconn()
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
        conn_pool.putconn(conn)
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
    conn = conn_pool.getconn()
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
        conn_pool.putconn(conn)
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
    conn = conn_pool.getconn()
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
        conn_pool.putconn(conn)
    return res
