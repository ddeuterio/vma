import os
import requests
import gzip
import shutil
import json

from dotenv import load_dotenv
from loguru import logger
from datetime import datetime, timedelta
from psycopg2.extras import Json
from ratelimit import limits, sleep_and_retry

import vma.connector as c


load_dotenv()

_api_key = os.getenv("NVD_API_KEY")

PERIOD = 30
MAX_REQ = 50
MAX_RETRIES = 3


@sleep_and_retry
@limits(calls=MAX_REQ, period=PERIOD)
def nvd_api_call(url, stream=None):
    """
    Auxiliar function to make API calls to NVD without surpasing the NVD API limit

    Args:
        URL to query
        Stream is True if gz file.

    Raises:
        Exception when the API call could not be performed
    """
    hd = {"apiKey": _api_key}

    i = 0
    while i < MAX_RETRIES:
        r = requests.get(url, stream=stream, headers=hd)
        if r.status_code == 200:
            break
        i += 1

    if (i >= MAX_RETRIES) or (not r.status_code == 200):
        logger.debug(f"Could not perform the API call: {r.status_code} {url}")
        raise Exception(f"Could not perform the API call: {r.status_code} {url}")
    return r


def download_and_extract_gz(url):
    """
    Auxiliar function used to download .gz json files and extract them

    Args:
        url to download

    Returns:
        json file name
    """
    r = nvd_api_call(url, stream=True)
    f_name = url.split("/")[-1]
    with open(f_name, "wb") as f:
        for chunk in r.iter_content(chunk_size=8192):
            if chunk:
                f.write(chunk)

    r.close()

    f_name_json = f_name.split(".gz")[0]
    with gzip.open(f_name, "rb") as f_in:
        with open(f_name_json, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)

    os.remove(f_name)
    logger.debug(f"File saved in disk: {f_name_json}")
    return f_name_json


def insert_vulnerabilities(f_meta, f_json):
    """
    Insert vulnerabilities from the json files into the database

    Args:
        meta data from the meta files
        json files
    """
    for i in range(len(f_json)):
        # parse data
        with open(f_json[i], "r") as f:
            data = json.load(f)
            parsed_data = parse_nvd_data(data=data["vulnerabilities"])
            # insert vuln
            c.insert_vulnerabilities(parsed_data[0], parsed_data[1])
        os.remove(f_json[i])
        c.insert_year_data(f_meta[i])


def get_modified_cves():
    """
    Checks the changes in the cves
    Gets the changes and updates the db
    """

    year = "recent"
    base_url = "https://nvd.nist.gov/feeds/json/cve/2.0"
    recents_url = f"{base_url}/nvdcve-2.0-recent.json.gz"

    r = nvd_api_call(f"{base_url}/nvdcve-2.0-{year}.meta")

    # first, check recents
    data = (r.text.splitlines()[0]).split("lastModifiedDate:")[1]
    data_iso = datetime.fromisoformat(data).astimezone()
    last_date = c.get_last_fetched_date(year)

    r.close()

    logger.debug(f"Dates data_iso: {data_iso}; last_date: {last_date}")

    if (not last_date) or (data_iso > last_date):
        if (data_iso - last_date) > timedelta(days=7):
            # check if there has been changes in files for years 2002 until now
            news = []
            meta = []
            for y in c.get_all_years_nvd_sync():
                # Get the last updated time for the year
                dt = c.get_nvd_sync_data(y)
                y_date = datetime.fromisoformat(dt[1]).astimezone()

                r = nvd_api_call(f"{base_url}/nvdcve-2.0-{y}.meta")
                nvd_date = datetime.fromisoformat(
                    (r.text.splitlines()[0]).split("lastModifiedDate:")[1]
                ).astimezone()
                nvd_chcksum = (r.text.splitlines()[-1]).split("sha256:")[1]
                # compare it with the latest meta of that year
                if (nvd_date > y_date) and (not (nvd_chcksum == dt[2])):
                    # there is a new file
                    news.append(y)
                    meta.append((y, nvd_date, nvd_chcksum))

            f_json = download_selected_cves(news)
            c.insert_year_data(
                ("recent", data_iso, (r.text.splitlines()[-1]).split("sha256:")[1])
            )
        else:
            # get the latest recent file
            f_json = [download_and_extract_gz(recents_url)]
            meta = [("recent", data_iso, (r.text.splitlines()[-1]).split("sha256:")[1])]

        insert_vulnerabilities(meta, f_json)
        logger.info("CVE DB updated with the latest changes")
    else:
        logger.info("No CVE updates, nothing was done")


def download_selected_cves(years):
    """
    Get all the json files for CVEs published over the course of (start year, end year)
    Args:
        List [] with the years to be updated

    Returns:
        List with filenames
    """

    f_names = []
    for year in years:
        url = f"https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz"
        f_names.append(download_and_extract_gz(url))
    return f_names


def init_db():
    """
    Get all the json files for CVEs published over the course of (2002, now) and updates the db
    """

    base_url = "https://nvd.nist.gov/feeds/json/cve/2.0"
    f_names = []
    meta = []
    y_range = [i for i in range(2002, (datetime.now().year + 1))]
    y_range.append("recent")
    for year in y_range:
        r = nvd_api_call(f"{base_url}/nvdcve-2.0-{year}.meta")
        nvd_date = datetime.fromisoformat(
            (r.text.splitlines()[0]).split("lastModifiedDate:")[1]
        ).astimezone()
        nvd_chcksum = (r.text.splitlines()[-1]).split("sha256:")[1]
        meta.append((year, nvd_date, nvd_chcksum))

        url = f"https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz"
        f_names.append(download_and_extract_gz(url))

    insert_vulnerabilities(meta, f_names)


def parse_nvd_data(data):
    """
    Takes the json data vulnerabilities[] and convert them into a format that can be used to store it in the database

    Args:
        data: json cve data

    Returns:
        List of tuples
        (id, sourceIdentifier, published, lastModified, vulnStatus, references, descriptions, weaknesses, configurations, cvss_data)

        where the following are in json format:
            descriptions, weaknesses, configurations

        and cvss_data has the following format:
            dict(
                cvss_version: [
                    (sourceA, vectorString, baseScore, base_severity),
                    (sourceB, vectorString, baseScore, base_severity),
                    ...
                ]
            )
    """
    p_data_cve = []  # list of tuples
    p_data_cvss = []  # list of tuples
    for vuln in data:
        id = vuln["cve"]["id"]
        sid = vuln["cve"]["sourceIdentifier"]
        pub = vuln["cve"]["published"]
        last_mod = vuln["cve"]["lastModified"]
        status = vuln["cve"]["vulnStatus"]
        references = ""
        for ref in vuln["cve"]["references"]:
            references += f"{ref['url']}, "
        references = references[:-2]  # remove the last " ,"
        # this will be stored as bjson
        descriptions = (
            Json(vuln["cve"]["descriptions"]) if "descriptions" in vuln["cve"] else None
        )
        weaknesses = (
            Json(vuln["cve"]["weaknesses"]) if "weaknesses" in vuln["cve"] else None
        )
        config = (
            Json(vuln["cve"]["configurations"])
            if "configurations" in vuln["cve"]
            else None
        )
        # metrics; cvss data
        for version in vuln["cve"]["metrics"].keys():
            for src in vuln["cve"]["metrics"][version]:
                if "baseSeverity" in src["cvssData"]:
                    base_severity = src["cvssData"]["baseSeverity"]
                else:
                    base_severity = src["baseSeverity"]
                p_data_cvss.append(
                    (
                        id,
                        src["source"],
                        src["cvssData"]["version"],
                        src["cvssData"]["vectorString"],
                        src["cvssData"]["baseScore"],
                        base_severity,
                    )
                )

        p_data_cve.append(
            (
                id,
                sid,
                pub,
                last_mod,
                status,
                references,
                descriptions,
                weaknesses,
                config,
            )
        )
    logger.info(f"{len(p_data_cve)} CVEs has been parsed")
    return [p_data_cve, p_data_cvss]

