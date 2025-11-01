import os
import psycopg2 as psql

from loguru import logger
from dotenv import load_dotenv
from psycopg2.extras import execute_values
from datetime import datetime

load_dotenv()

_db_host = os.getenv('DB_HOST')
_db_user = os.getenv('DB_USER')
_db_pass = os.getenv('DB_PASS')
_db_name = os.getenv('DB_NAME')

queries = {
    'get_fetch_date': "SELECT last_fetched FROM nvd_sync WHERE id = %s;",
    'get_nvd_sync_data': "SELECT id, last_fetched, chcksum FROM nvd_sync WHERE id = %s;",
    'get_all_years_nvd_sync': "SELECT id FROM nvd_sync WHERE id != 'recent';",
    'get_cves': """
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
    'insert_cve': """
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
    'insert_cvss': """
        INSERT INTO cvss_metrics
            (cve_id, source, cvss_version, vector_string, base_score, base_severity)
        VALUES %s
        ON CONFLICT (cve_id, source, cvss_version)
        DO UPDATE SET
            vector_string = EXCLUDED.vector_string,
            base_score = EXCLUDED.base_score,
            base_severity = EXCLUDED.base_severity;
    """,
    'insert_fetch_date': """
        INSERT INTO nvd_sync
            (id, last_fetched, chcksum)
        VALUES (%s, %s, %s)
        ON CONFLICT (id)
        DO UPDATE SET
            last_fetched = EXCLUDED.last_fetched,
            chcksum = EXCLUDED.chcksum;    
    """,
    'get_products': 'SELECT id, description FROM products ORDER BY id;',
    'get_product': "SELECT id, description FROM products WHERE id = %s;",
    'insert_product': 'INSERT INTO products (id, description) VALUES (%s, %s) RETURNING id;',
    'delete_product': "DELETE FROM products WHERE id = %s;",
    'insert_image': 'INSERT INTO images (name, version, product) VALUES (%s, %s, %s) RETURNING name, version, product;',
    'get_images': 'SELECT name, version, product FROM images ORDER BY product, name, version;',
    'get_images_by_product': 'SELECT name, version, product FROM images WHERE product = %s ORDER BY name, version;',
    'get_images_by_name_product': "SELECT name, version, product FROM images WHERE name = %s AND product = %s;",
    'get_image_by_name_version_product': "SELECT name, version, product FROM images WHERE name = %s AND version = %s AND product = %s;",
    'delete_image_by_name': "DELETE FROM images WHERE name = %s AND product = %s;",
    'delete_image_by_name_version': "DELETE FROM images WHERE name = %s AND version = %s AND product = %s;",
    'get_image_vulnerabilities': """
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
        ORDER BY
            iv.cve,
            iv.affected_component;
    """,
    'insert_image_vulnerabilities': """
        INSERT INTO image_vulnerabilities (image_name, image_version, product, cve, fix_versions, first_seen, last_seen, affected_component_type, affected_component, affected_version, affected_path)
        VALUES %s
        ON CONFLICT (image_name, image_version, product, cve, affected_component_type, affected_component)
        DO UPDATE SET
            last_seen = EXCLUDED.last_seen;
    """,
    'compare_image_versions': """
        WITH image_a AS (
            SELECT DISTINCT
                cve,
                affected_component_type,
                affected_component,
                affected_path
            FROM image_vulnerabilities
            WHERE product = %s
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
            WHERE product = %s
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
}

def get_all_years_nvd_sync():
    """
    Gets the date (extended ISO-8601 date/time format) of the last time that the database was updated for all years.

    Returns:
        Date of the last time that the vulnerabilities where updated
    """
    dt = None
    try:
        with psql.connect(host=_db_host, dbname=_db_name, user=_db_user, password=_db_pass) as conn:
            with conn.cursor() as cur:
                cur.execute(queries['get_nvd_sync_data'])
                dt = cur.fetchall()
                logger.debug(f"get_all_years_nvd_sync; All years gotten from the nvd_sync table")
    except psql.Error as e:
        logger.error(f"get_all_years_nvd_sync; psql error: {e}")
    except Exception as e:
        logger.error(f"get_all_years_nvd_sync; db error: {e}")

    res = [i[0] for i in dt] if dt else None
    return res


def get_nvd_sync_data(year):
    """
    Gets the date (extended ISO-8601 date/time format) of the last time that the database was updated.

    Returns:
        Date of the last time that the vulnerabilities where updated
    """
    dt = None
    try:
        with psql.connect(host=_db_host, dbname=_db_name, user=_db_user, password=_db_pass) as conn:
            with conn.cursor() as cur:
                cur.execute(queries['get_nvd_sync_data'], year)
                dt = cur.fetchone()
                logger.debug(f"get_nvd_sync_data; Last date when {year} CVE data was updated was {dt}")
    except psql.Error as e:
        logger.error(f"get_nvd_sync_data; psql error: {e}")
    except Exception as e:
        logger.error(f"get_nvd_sync_data; db error: {e}")
    return dt


def get_last_fetched_date(year):
    """
    Gets the date (extended ISO-8601 date/time format) of the last time that the database was updated.

    Returns:
        Date of the last time that the vulnerabilities where updated
    """
    dt = None
    try:
        with psql.connect(host=_db_host, dbname=_db_name, user=_db_user, password=_db_pass) as conn:
            with conn.cursor() as cur:
                cur.execute(queries['get_fetch_date'], (year,))
                dt = cur.fetchone()
                logger.debug(f"Last date when CVE data was updated was {dt[0]}")
    except psql.Error as e:
        logger.error(f"get_last_fetched_date; psql error: {e}")
    except Exception as e:
        logger.error(f"get_last_fetched_date; db error: {e}")

    res = datetime.fromisoformat(dt[0]).astimezone() if dt else None
    return res


def insert_year_data(value):
    """
    Update the date of the last fetched value (extended ISO-8601 date/time format)
    
    Args:
        value gotten from the last recent file
    Returns:
        Boolean with the result of the query
    """
    res = True
    try:
        with psql.connect(host=_db_host, dbname=_db_name, user=_db_user, password=_db_pass) as conn:
            with conn.cursor() as cur:
                cur.execute(queries['insert_fetch_date'], value)
                conn.commit()
                logger.debug(f"insert_year_data; Last fetched date was updated to {value}")
    except psql.Error as e:
        logger.error(f"insert_year_data; psql error: {e}")
        res = False
    except Exception as e:
        logger.error(f"insert_year_data; db error: {e}")
        res = False
    return res


def insert_vulnerabilities(data_cve, data_cvss):
    """
    Inserts bulk data into the DB
    
    Args:
        NVD json data parsed using function nvd.parse_nvd_data() for CVE and CVSS

    Returns:
        dict structure with 'status' and 'result'
    """
    res = True
    try:
        with psql.connect(host=_db_host, dbname=_db_name, user=_db_user, password=_db_pass) as conn:
            with conn.cursor() as cur:
                execute_values(cur, queries['insert_cve'], data_cve)
                conn.commit()
                execute_values(cur, queries['insert_cvss'], data_cvss)
                conn.commit()

    except psql.Error as e:
        logger.error(f"insert_vulnerabilities; psql error: {e}")
        res = False
    except Exception as e:
        logger.error(f"insert_vulnerabilities; db error: {e}")
        res = False
    return {'status': res, 'result': {'num_cve': len(data_cve)}}


def get_vulnerabilities_by_id(id):
    """
    Get the vulnerabilities based on the cve id pattern

    Args:
        id: cve id pattern
    
    Returns:
        dict structure with 'status' and 'result'
    """
    res = {'status': True, 'result': {}}
    try:
        with psql.connect(host=_db_host, dbname=_db_name, user=_db_user, password=_db_pass) as conn:
            with conn.cursor() as cur:
                cur.execute(queries['get_cves'], (id,))
                aux = cur.fetchall()
        logger.debug(f"get_vulnerabilities_by_id; A total of {len(aux)} vulnerabilities have been found for the filter {id}")
        
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

            if not (cve_id in res['result']):
                res['result'][cve_id] = {
                    'source': source_identifier,
                    'published_date': published_date,
                    'last_modified': last_modified,
                    'status': status,
                    'references': refs,
                    'descriptions': descriptions,
                    'weakness': weakness,
                    'configurations': configs,
                    'cvss': {}
                }
            
            if not (cvss_version in res['result'][cve_id]['cvss']):
                res['result'][cve_id]['cvss'][cvss_version] = []
            res['result'][cve_id]['cvss'][cvss_version].append(
                {
                    'source': cvss_source,
                    'vector_string': cvss_vs,
                    'base_score': cvss_bscore,
                    'base_severity': cvss_bsev
                }
            )
        if not res['result']:
            res['status'] = False
    except psql.Error as e:
        logger.error(f"get_vulnerabilities_by_id; psql error: {e}")
        return {'status': False, 'result': None}
    except Exception as e:
        logger.error(f"get_vulnerabilities_by_id; db error: {e}")
        return {'status': False, 'result': None}
    return res


def insert_product(values):
    """
    Inserts a new product
    
    Args:
        values: (product name (id), product description)
            
    Returns:
        dict structure with 'status' and 'result'
    """
    res = {'status': True, 'result': None}
    try:
        with psql.connect(host=_db_host, dbname=_db_name, user=_db_user, password=_db_pass) as conn:
            with conn.cursor() as cur:
                cur.execute(queries['insert_product'], values)
                q = cur.fetchone()[0]
                conn.commit()
                if not res:
                    res['status'] = False
                else:
                    res['result'] = {"id": q}
                logger.debug(f"insert_product; New product with name {values} was created")
    except psql.Error as e:
        logger.error(f"insert_product; psql error: {e}")
        return {'status': False, 'result': None}
    except Exception as e:
        logger.error(f"insert_product; db error: {e}")
        return {'status': False, 'result': None}
    return res


def get_products(id=None):
    """
    Retrieve products.

    Returns:
        dict structure with 'status' and 'result'
    """
    res = {'status': True, 'result': []}
    try:
        with psql.connect(host=_db_host, dbname=_db_name, user=_db_user, password=_db_pass) as conn:
            with conn.cursor() as cur:
                logger.debug(f"get_products; id: {id}")
                if id:
                    cur.execute(queries['get_product'], (id,))
                    
                else:
                    cur.execute(queries['get_products'])
                q = cur.fetchall()
                if not q:
                    res['status'] = False
                else:
                    for p in q:
                        res['result'].append({'id': p[0], 'description': p[1]})
    except psql.Error as e:
        logger.error(f"get_products; psql error: {e}")
        return {'status': False, 'result': None}
    except Exception as e:
        logger.error(f"get_products; db error: {e}")
        return {'status': False, 'result': None}
    return res


def insert_image(values):
    """
    Inserts a new image
    
    Args:
        values: (image name, image description, product id associated with the image)
    Returns:
        dict structure with 'status' and 'result'
    """
    res = {'status': True, 'result': {}}
    try:
        with psql.connect(host=_db_host, dbname=_db_name, user=_db_user, password=_db_pass) as conn:
            with conn.cursor() as cur:
                cur.execute(queries['insert_image'], values)
                q = cur.fetchone()
                conn.commit()
                if not q:
                    res['status'] = False
                else:
                    res['result'] = {'name': q[0], 'version': q[1], 'product': q[2]}
                logger.debug(f"insert_image; New image with name {values} was created")
    except psql.Error as e:
        logger.error(f"insert_image; psql error: {e}")
        return {'status': False, 'result': None}
    except Exception as e:
        logger.error(f"insert_image; db error: {e}")
        return {'status': False, 'result': None}
    return res


def get_images(name=None, version=None, product=None):
    """
    Retrieve images, optionally filtered by product.

    Args:
        values: (name, version, product)

    Returns:
        dict structure with 'status' and 'result'
    """
    res = {'status': True, 'result': []}
    try:
        with psql.connect(host=_db_host, dbname=_db_name, user=_db_user, password=_db_pass) as conn:
            with conn.cursor() as cur:
                if product and name and version:
                    cur.execute(queries['get_image_by_name_version_product'], (name, version, product))
                elif product and name:
                    cur.execute(queries['get_images_by_name_product'], (name, product))
                elif product:
                    cur.execute(queries['get_images_by_product'], (product,))
                else:
                    cur.execute(queries['get_images'])
                q = cur.fetchall()
                if not q:
                    res['status'] = False
                else:
                    for im in q:
                        res['result'].append({'name': im[0], 'version': im[1], 'product': im[2]})
    except psql.Error as e:
        logger.error(f"get_images_by_product; psql error: {e}")
        return {'status': False, 'result': None}
    except Exception as e:
        logger.error(f"get_images_by_product; db error: {e}")
        return {'status': False, 'result': None}
    return res


def insert_image_vulnerabilities(values):
    """
    Bind a vulnerability with an image
    
    Args:
        values: (image_id, vuln_id, first_seen, last_seen, affected_component, affected_path)
    Returns:
        dict structure with 'status' and 'result'
    """
    try:
        with psql.connect(host=_db_host, dbname=_db_name, user=_db_user, password=_db_pass) as conn:
            with conn.cursor() as cur:
                execute_values(cur, queries['insert_image_vulnerabilities'], values)
                conn.commit()
                logger.debug(f"insert_image_vulnerabilities; A total of {len(values)} have been inserted")
    except psql.Error as e:
        logger.error(f"insert_image_vulnerabilities; psql error: {e}")
        return {'status': False, 'result': None}
    except Exception as e:
        logger.error(f"insert_image_vulnerabilities; db error: {e}")
        return {'status': False, 'result': None}
    return {'status': True, 'result': {'num_cve': len(values)}}


def get_image_vulnerabilities(product, name, version):
    """
    Get the vulnerabilities associated to an image

    Args:
        product
        name
        version
    Returns:
        dict structure with 'status' and 'result'
    """
    res = {'status': True, 'result': None}
    try:
        with psql.connect(host=_db_host, dbname=_db_name, user=_db_user, password=_db_pass) as conn:
            with conn.cursor() as cur:
                cur.execute(queries['get_image_vulnerabilities'], (product, name, version))
                q = cur.fetchall()
                if not q:
                    res['status'] = False
                else:
                    res['result'] = q
                logger.debug(f"get_image_vulnerabilities; Vulns for image {product} {name}:{version}")
    except psql.Error as e:
        logger.error(f"get_image_vulnerabilities; psql error: {e}")
        return {'status': False, 'result': None}
    except Exception as e:
        logger.error(f"get_image_vulnerabilities; db error: {e}")
        return {'status': False, 'result': None}
    return res


def compare_image_versions(product, image, version_a, version_b):
    """
    Given two versions for the same product, same image, provide details on the vulnerabilities that are shared and not shared.

    Params:
        product
        image
        version_a
        version_b
    Returns:
        dict structure with 'status' and 'result'
    """
    res = {'status': True, 'result': None}
    try:
        with psql.connect(host=_db_host, dbname=_db_name, user=_db_user, password=_db_pass) as conn:
            with conn.cursor() as cur:
                cur.execute(queries['compare_image_versions'], (product, image, version_a, product, image, version_b))
                q = cur.fetchall()
                if not q:
                    res['status'] = False
                else:
                    res['result'] = q
                logger.debug(f"compare_image_versions; Data from the two versions gotten")
    except psql.Error as e:
        logger.error(f"compare_image_versions; psql error: {e}")
        return {'status': False, 'result': None}
    except Exception as e:
        logger.error(f"compare_image_versions; db error: {e}")
        return {'status': False, 'result': None}
    return res


def delete_product(id):
    """
    Delete a product

    Args:
        value: product id
    
    Returns:
        dict structure with 'status' and 'result'
    """
    res = {'status': True, 'result': None}
    try:
        with psql.connect(host=_db_host, dbname=_db_name, user=_db_user, password=_db_pass) as conn:
            with conn.cursor() as cur:
                cur.execute(queries['delete_product'], (id,))
                if not cur.rowcount:
                    res['status'] = False
                else:
                    res['result'] = {'deleted_rows': cur.rowcount}
    except psql.Error as e:
        logger.error(f"delete_product; psql error: {e}")
        return {'status': False, 'result': None}
    except Exception as e:
        logger.error(f"delete_product; db error: {e}")
        return {'status': False, 'result': None}
    return res


def delete_image(product, name=None, version=None):
    """
    Deletes images

    Args:
        product: id
        name: image name
        version: image version
    
    Returns:
        dict structure with 'status' and 'result'
    """
    res = {'status': True, 'result': None}
    try:
        with psql.connect(host=_db_host, dbname=_db_name, user=_db_user, password=_db_pass) as conn:
            with conn.cursor() as cur:
                if version and name: 
                    cur.execute(queries['delete_image_by_name_version'], (name, version, product))
                elif name:
                    cur.execute(queries['delete_image_by_name'], (name, product))
                if not cur.rowcount:
                    res['status'] = False
                else:
                    res['result'] = {'deleted_rows': cur.rowcount}
    except psql.Error as e:
        logger.error(f"delete_product; psql error: {e}")
        return {'status': False, 'result': None}
    except Exception as e:
        logger.error(f"delete_product; db error: {e}")
        return {'status': False, 'result': None}
    return res