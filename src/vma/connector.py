import logging
from dotenv import load_dotenv
import os
import psycopg2 as psql
from psycopg2.extras import execute_values
from datetime import datetime

_logger = logging.getLogger(__name__)

load_dotenv()

_db_host = os.getenv('DB_HOST')
_db_user = os.getenv('DB_USER')
_db_pass = os.getenv('DB_PASS')
_db_name = os.getenv('DB_NAME')

queries = {
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
    'insert_product': 'INSERT INTO products (id, description) VALUES (%s, %s) RETURNING id;',
    'insert_image': 'INSERT INTO images (name, version, product) VALUES (%s, %s, %s) RETURNING name, version, product;',
    'insert_image_vulnerabilities': """
        INSERT INTO image_vulnerabilities (image_name, image_version, product, cve, fix_versions, first_seen, last_seen, affected_component_type, affected_component, affected_version, affected_path)
        VALUES %s
        ON CONFLICT (image_name, image_version, product, cve, affected_component_type, affected_component)
        DO UPDATE SET
            last_seen = EXCLUDED.last_seen;
    """,
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
            vulnerabilities.cve_id ILIKE %s;
    """,
    'get_product': "SELECT id, description FROM products WHERE id = %s;",
    'get_image': "SELECT name, version, product FROM images WHERE name = %s AND version = %s AND product = %s;",
    'get_image_vulnerabilities': """
        SELECT
            images.name,
            images.version,
            images.product,
            image_vulnerabilities.vuln_id,
            image_vulnerabilities.first_seen,
            image_vulnerabilities.last_seen,
            image_vulnerabilities.affected_component,
            image_vulnerabilities.affected_path
        FROM
            images
        INNER JOIN
            images_vulnerabilities
        ON
            images.id = images_vulnerabilities.image_id
        WHERE
            image_id = %s;
    """
}

def get_all_years_nvd_sync():
    """
    Gets the date (extended ISO-8601 date/time format) of the last time that the database was updated for all years.

    Returns:
        Date of the last time that the vulnerabilities where updated
        None is there is an error
    """
    dt = None
    try:
        with psql.connect(host=_db_host, dbname=_db_name, user=_db_user, password=_db_pass) as conn:
            with conn.cursor() as cur:
                cur.execute(queries['get_nvd_sync_data'])
                dt = cur.fetchall()
                _logger.debug(f"All years gotten from the nvd_sync table")
    except psql.Error as e:
        _logger.error(f"get_all_years_nvd_sync; psql error: {e}")
    except Exception as e:
        _logger.error(f"get_all_years_nvd_sync; db error: {e}")

    res = [i[0] for i in dt] if dt else None
    return res


def get_nvd_sync_data(year):
    """
    Gets the date (extended ISO-8601 date/time format) of the last time that the database was updated.

    Returns:
        Date of the last time that the vulnerabilities where updated
        None if there is an error
    """
    dt = None
    try:
        with psql.connect(host=_db_host, dbname=_db_name, user=_db_user, password=_db_pass) as conn:
            with conn.cursor() as cur:
                cur.execute(queries['get_nvd_sync_data'], year)
                dt = cur.fetchone()
                _logger.debug(f"Last date when {year} CVE data was updated was {dt}")
    except psql.Error as e:
        _logger.error(f"get_nvd_sync_data; psql error: {e}")
    except Exception as e:
        _logger.error(f"get_nvd_sync_data; db error: {e}")

    return dt


def get_last_fetched_date(year):
    """
    Gets the date (extended ISO-8601 date/time format) of the last time that the database was updated.

    Returns:
        Date of the last time that the vulnerabilities where updated
        None if there is an error
    """
    dt = None
    try:
        with psql.connect(host=_db_host, dbname=_db_name, user=_db_user, password=_db_pass) as conn:
            with conn.cursor() as cur:
                cur.execute(queries['get_fetch_date'], (year,))
                dt = cur.fetchone()
                _logger.debug(f"Last date when CVE data was updated was {dt[0]}")
    except psql.Error as e:
        _logger.error(f"get_last_fetched_date; psql error: {e}")
    except Exception as e:
        _logger.error(f"get_last_fetched_date; db error: {e}")

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
                _logger.debug(f"Last fetched date was updated to {value}")
    except psql.Error as e:
        _logger.error(f"insert_year_data; psql error: {e}")
        res = False
    except Exception as e:
        _logger.error(f"insert_year_data; db error: {e}")
        res = False
    return res


def insert_vulnerabilities(data_cve, data_cvss):
    """
    Inserts bulk data into the DB
    
    Args:
        NVD json data parsed using function nvd.parse_nvd_data() for CVE and CVSS

    Returns:
        Boolean with the results of the query
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
        _logger.error(f"insert_vulnerabilities; psql error: {e}")
        res = False
    except Exception as e:
        _logger.error(f"insert_vulnerabilities; db error: {e}")
        res = False
    return res


def get_vulnerabilities(values):
    """
    Get the vulnerabilities based on the filters provided by the user

    Args:
        values: filters provided by the user after sanitization
    
    Returns:
        List of tuples with the results from the db
    """
    res = {}
    try:
        with psql.connect(host=_db_host, dbname=_db_name, user=_db_user, password=_db_pass) as conn:
            with conn.cursor() as cur:
                cur.execute(queries['get_cves'], values)
                aux = cur.fetchall()

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

            if not (cve_id in res):
                res[cve_id] = {
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
            
            if not (cvss_version in res[cve_id]['cvss']):
                res[cve_id]['cvss'][cvss_version] = []
            res[cve_id]['cvss'][cvss_version].append(
                {
                    'source': cvss_source,
                    'vector_string': cvss_vs,
                    'base_score': cvss_bscore,
                    'base_severity': cvss_bsev
                }
            )
    except psql.Error as e:
        _logger.error(f"psql error: {e}")
    except Exception as e:
        _logger.error(f"db error: {e}")

    return res


def insert_product(values):
    """
    Create a new product
    
    Args:
        list with two strings:
            product name (id)
            product description
    Returns:
        id of the newly created product
    """
    res = None
    try:
        with psql.connect(host=_db_host, dbname=_db_name, user=_db_user, password=_db_pass) as conn:
            with conn.cursor() as cur:
                cur.execute(queries['insert_product'], values)
                res = cur.fetchone()[0]
                conn.commit()
                _logger.debug(f"New product with name {values} was created")
    except psql.Error as e:
        _logger.error(f"insert_product; psql error: {e}")
    except Exception as e:
        _logger.error(f"insert_product; db error: {e}")
    return res


def insert_image(values):
    """
    Create a new image
    
    Args:
        list with three strings:
            image name
            image description
            product id associated with the image
    Returns:
        id of the newly created image
    """
    res = None
    try:
        with psql.connect(host=_db_host, dbname=_db_name, user=_db_user, password=_db_pass) as conn:
            with conn.cursor() as cur:
                cur.execute(queries['insert_image'], values)
                res = cur.fetchone()
                conn.commit()
                _logger.debug(f"New image with name {values} was created")
    except psql.Error as e:
        _logger.error(f"insert_image; psql error: {e}")
    except Exception as e:
        _logger.error(f"insert_image; db error: {e}")
    return res


def insert_image_vulnerabilities(values):
    """
    Bind a vulnerability with an image
    
    Args:
        list with seven strings:
            [ image_id, vuln_id, first_seen, last_seen, affected_component, affected_path ]
    Returns:
        Boolean with the result of the query
    """
    res = True
    try:
        with psql.connect(host=_db_host, dbname=_db_name, user=_db_user, password=_db_pass) as conn:
            with conn.cursor() as cur:
                execute_values(cur, queries['insert_image_vulnerabilities'], values)
                conn.commit()
                _logger.debug(f"{values[2]} binded with {values[0]}")
    except psql.Error as e:
        _logger.error(f"insert_image_vulnerabilities; psql error: {e}")
        res = False
    except Exception as e:
        _logger.error(f"insert_image_vulnerabilities; db error: {e}")
        res = False
    return res

def get_product(value):
    """
    Get the product based on the id

    Args:
        value: product id
    
    Returns:
        Details for the product
    """
    res = None
    try:
        with psql.connect(host=_db_host, dbname=_db_name, user=_db_user, password=_db_pass) as conn:
            with conn.cursor() as cur:
                cur.execute(queries['get_product'], value)
                res = cur.fetchone()
    except psql.Error as e:
        _logger.error(f"psql error: {e}")
    except Exception as e:
        _logger.error(f"db error: {e}")

    return res

def get_image(values):
    """
    Get the image based on (name, version, product)

    Args:
        values: tuple with (name, version, product)
    
    Returns:
        Details for the image
    """
    res = None
    try:
        with psql.connect(host=_db_host, dbname=_db_name, user=_db_user, password=_db_pass) as conn:
            with conn.cursor() as cur:
                cur.execute(queries['get_image'], values)
                res = cur.fetchone()
    except psql.Error as e:
        _logger.error(f"psql error: {e}")
    except Exception as e:
        _logger.error(f"db error: {e}")

    return res

def get_image_vulnerabilities(values):
    """
    Get the vulnerabilities associated to an image

    Args:
        values: image_id
    
    Returns:
        List of tuples with the results from the db
    """
    res = None
    try:
        with psql.connect(host=_db_host, dbname=_db_name, user=_db_user, password=_db_pass) as conn:
            with conn.cursor() as cur:
                cur.execute(queries['get_image_vulnerabilities'], values)
                res = cur.fetchall()
    except psql.Error as e:
        _logger.error(f"psql error: {e}")
    except Exception as e:
        _logger.error(f"db error: {e}")

    return res