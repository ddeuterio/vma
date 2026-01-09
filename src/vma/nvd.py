import os
import asyncio
import gzip
import shutil
import json

import httpx
import aiofiles
from dotenv import load_dotenv
from loguru import logger
from datetime import datetime, timedelta
from aiolimiter import AsyncLimiter

import vma.connector as c


load_dotenv()

_api_key = os.getenv("NVD_API_KEY")

PERIOD = 30
MAX_REQ = 50
MAX_RETRIES = 3

# Create async rate limiter (50 requests per 30 seconds)
rate_limiter = AsyncLimiter(MAX_REQ, PERIOD)


async def nvd_api_call(url):
    """
    Async function to make API calls to NVD without surpassing the NVD API limit.
    Uses httpx for async HTTP and aiolimiter for rate limiting.

    Args:
        url: URL to query

    Returns:
        httpx.Response object

    Raises:
        Exception when the API call could not be performed after retries
    """
    hd = {"apiKey": _api_key}
    i = 0
    r = None

    async with rate_limiter:
        async with httpx.AsyncClient(timeout=30.0) as client:
            while i < MAX_RETRIES:
                r = await client.get(url, headers=hd, follow_redirects=True)  # type: ignore[arg-type]
                if r.status_code == 200:
                    break
                i += 1

    if (not r) or (i >= MAX_RETRIES) or (not r.status_code == 200):
        status_code = r.status_code if r else ""
        logger.debug(f"Could not perform the API call: {status_code} {url}")
        raise Exception(f"Could not perform the API call: {status_code} {url}")
    return r


def _decompress_gz(f_name, f_name_json):
    """
    Helper for CPU-bound gzip decompression.
    Runs in thread pool to avoid blocking event loop.
    """
    with gzip.open(f_name, "rb") as f_in:
        with open(f_name_json, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)  # type: ignore[arg-type]


async def download_and_extract_gz(url):
    """
    Async function to download .gz json files and extract them.
    Uses aiofiles for async file I/O and runs gzip decompression in thread pool.

    Args:
        url: URL to download

    Returns:
        str: Extracted JSON file name
    """
    r = await nvd_api_call(url)
    f_name = url.split("/")[-1]

    # Write .gz file asynchronously
    async with aiofiles.open(f_name, "wb") as f:
        await f.write(r.content)

    # Decompress in thread pool (CPU-bound operation)
    f_name_json = f_name.split(".gz")[0]
    await asyncio.to_thread(_decompress_gz, f_name, f_name_json)

    # Remove .gz file in thread pool
    await asyncio.to_thread(os.remove, f_name)

    logger.debug(f"File saved in disk: {f_name_json}")
    return f_name_json


async def insert_vulnerabilities(f_meta, f_json):
    """
    Insert vulnerabilities from the JSON files into the database.
    Async version using aiofiles and awaiting database operations.

    Args:
        f_meta: List of metadata tuples from the meta files
        f_json: List of JSON file paths
    """
    for i in range(len(f_json)):
        async with aiofiles.open(f_json[i], "r") as f:
            content = await f.read()
            data = json.loads(content)
            parsed_data = parse_nvd_data(data=data["vulnerabilities"])
            await c.insert_vulnerabilities(parsed_data[0], parsed_data[1])

        await asyncio.to_thread(os.remove, f_json[i])
        await c.insert_year_data(f_meta[i])


async def get_modified_cves():
    """
    Async function to check for CVE changes and update the database.
    Compares NVD meta timestamps with local database and fetches updates.
    """
    year = "recent"
    base_url = "https://nvd.nist.gov/feeds/json/cve/2.0"
    recents_url = f"{base_url}/nvdcve-2.0-recent.json.gz"

    r = await nvd_api_call(f"{base_url}/nvdcve-2.0-{year}.meta")

    # First, check recents
    data = (r.text.splitlines()[0]).split("lastModifiedDate:")[1]
    data_iso = datetime.fromisoformat(data).astimezone()
    last_date = await c.get_last_fetched_date(year)

    logger.debug(f"Dates data_iso: {data_iso}; last_date: {last_date}")

    if (not last_date) or (data_iso > last_date):
        # Check if we need to do a full sync (>7 days difference or no previous sync)
        if (not last_date) or ((data_iso - last_date) > timedelta(days=7)):
            # Check if there has been changes in files for years 2002 until now
            news = []
            meta = []
            for y in await c.get_all_years_nvd_sync():
                # Get the last updated time for the year
                dt = await c.get_nvd_sync_data(y)
                _date = datetime.fromisoformat(dt[1]).astimezone()

                r = await nvd_api_call(f"{base_url}/nvdcve-2.0-{y}.meta")
                nvd_date = datetime.fromisoformat(
                    (r.text.splitlines()[0]).split("lastModifiedDate:")[1]
                ).astimezone()
                nvd_chcksum = (r.text.splitlines()[-1]).split("sha256:")[1]
                if (nvd_date > _date) and (not (nvd_chcksum == dt[2])):
                    # There is a new file
                    news.append(y)
                    meta.append((y, nvd_date, nvd_chcksum))

            f_json = await download_selected_cves(news)
            await c.insert_year_data(
                ("recent", data_iso, (r.text.splitlines()[-1]).split("sha256:")[1])
            )
        else:
            # Get the latest recent file
            f_json = [await download_and_extract_gz(recents_url)]
            meta = [("recent", data_iso, (r.text.splitlines()[-1]).split("sha256:")[1])]

        await insert_vulnerabilities(meta, f_json)
        logger.info("CVE DB updated with the latest changes")
    else:
        logger.info("No CVE updates, nothing was done")


async def download_selected_cves(years):
    """
    Async function to download JSON files for CVEs published for specified years.

    Args:
        years: List of years to download

    Returns:
        List of downloaded JSON filenames
    """
    f_names = []
    for year in years:
        url = f"https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz"
        f_names.append(await download_and_extract_gz(url))
    return f_names


async def init_db():
    """
    Async function to initialize database with all CVE data from 2002 to present.
    Downloads and processes all NVD CVE JSON files.
    """
    base_url = "https://nvd.nist.gov/feeds/json/cve/2.0"
    f_names = []
    meta = []
    y_range = [i for i in range(2002, (datetime.now().year + 1))]
    y_range.append("recent")  # type: ignore[arg-type]

    for year in y_range:
        r = await nvd_api_call(f"{base_url}/nvdcve-2.0-{year}.meta")
        nvd_date = datetime.fromisoformat(
            (r.text.splitlines()[0]).split("lastModifiedDate:")[1]
        ).astimezone()
        nvd_chcksum = (r.text.splitlines()[-1]).split("sha256:")[1]
        meta.append((year, nvd_date, nvd_chcksum))

        url = f"https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz"
        f_names.append(await download_and_extract_gz(url))

    await insert_vulnerabilities(meta, f_names)


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
        # Store as plain dicts/lists - asyncpg handles JSON serialization automatically
        descriptions = (
            vuln["cve"]["descriptions"] if "descriptions" in vuln["cve"] else None
        )
        weaknesses = vuln["cve"]["weaknesses"] if "weaknesses" in vuln["cve"] else None
        config = (
            vuln["cve"]["configurations"] if "configurations" in vuln["cve"] else None
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
