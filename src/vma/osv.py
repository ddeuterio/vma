from loguru import logger

import os
import asyncio
import json
import shutil
from google.cloud import storage
from google.cloud.exceptions import NotFound, Forbidden
import zipfile
from psycopg2.extras import Json
import csv
from datetime import datetime
from io import StringIO

import aiofiles

from vma import connector as c


async def download_gcs_bucket(prefix: str, name: str, dst: str) -> str:
    """
    Download a file from GCS bucket using thread pool to avoid blocking.
    """
    local_path = os.path.join(dst, name)

    # Run blocking GCS operations in thread pool
    def _download():
        try:
            c = storage.Client.create_anonymous_client()
            b = c.bucket(prefix)
            if not b.exists():
                logger.error(f"Bucket {name} does not exist")
                raise Exception(f"Bucket {name} does not exist")

            blob = b.blob(name)

            if not blob:
                logger.error(f"No files found in bucket {name}")
                raise Exception(f"No files found in bucket {name}")

            logger.debug("Files found in bucket")

            # Create directory if needed
            os.makedirs(os.path.dirname(local_path), exist_ok=True)

            # Download file
            blob.download_to_filename(local_path)
            logger.debug(f"Downloaded: {local_path}")
            return local_path
        except NotFound:
            logger.error(f"Bucket {name} not found")
            return ""
        except Forbidden:
            logger.error(f"Access denied to bucket {name}")
            return ""
        except Exception as e:
            logger.error(f"Error while downloading the gcs bucket {name}: {e}")
            return ""

    # Execute in thread pool
    result = await asyncio.to_thread(_download)
    return result


async def unzip_file(name):
    """
    Extract zip file using thread pool (CPU-bound operation).
    """
    extracted = "osv/all/extracted/"

    # Run CPU-bound extraction in thread pool
    def _extract():
        with zipfile.ZipFile(name, "r") as zip_ref:
            zip_ref.extractall(extracted)
        return extracted

    result = await asyncio.to_thread(_extract)
    logger.debug(f"File {name} unziped in {extracted}")
    return result


async def get_all():
    fname = await download_gcs_bucket(
        prefix="osv-vulnerabilities", name="all.zip", dst="osv/all"
    )
    ufile = await unzip_file(fname)
    return ufile


async def get_recent():
    fname = await download_gcs_bucket(
        prefix="osv-vulnerabilities", name="modified_id.csv", dst="osv/recent"
    )
    return fname


async def clean_osv_files(path):
    """
    Clean up OSV files and directories after processing.
    Uses thread pool for filesystem operations.

    Args:
        path: Path to file or directory to delete
    """
    if not path:
        logger.debug(f"Empty path provided, nothing to clean")
        return

    # Run filesystem checks in thread pool
    exists = await asyncio.to_thread(os.path.exists, path)
    if not exists:
        logger.debug(f"Path does not exist, nothing to clean: {path}")
        return

    try:
        is_file = await asyncio.to_thread(os.path.isfile, path)
        if is_file:
            await asyncio.to_thread(os.remove, path)
            logger.debug(f"Deleted file: {path}")
        else:
            is_dir = await asyncio.to_thread(os.path.isdir, path)
            if is_dir:
                await asyncio.to_thread(shutil.rmtree, path)
                logger.debug(f"Deleted directory: {path}")
    except Exception as e:
        logger.error(f"Error cleaning up {path}: {e}")


async def parse_osv_file(path):
    """
    Parses an OSV (Open Source Vulnerability) JSON file and converts it to VMA OSV database format.

    Args:
        path: Path to the OSV JSON file

    Returns:
        List containing [data_vuln, data_aliases, data_refs, data_severity, data_affected, data_credits] where:
        - data_vuln: List of tuples for osv_vulnerabilities table
          (osv_id, schema_version, modified, published, withdrawn, summary, details, database_specific)
        - data_aliases: List of tuples for osv_aliases table
          (osv_id, alias)
        - data_refs: List of tuples for osv_references table
          (osv_id, ref_type, url)
        - data_severity: List of tuples for osv_severity table
          (osv_id, severity_type, score)
        - data_affected: List of tuples for osv_affected table
          (osv_id, package_ecosystem, package_name, package_purl, ranges, versions, ecosystem_specific, database_specific)
        - data_credits: List of tuples for osv_credits table
          (osv_id, name, contact, credit_type)
    """
    data_vuln = []
    data_aliases = []
    data_refs = []
    data_severity = []
    data_affected = []
    data_credits = []

    try:
        async with aiofiles.open(path, "r") as f:
            content = await f.read()
            osv_data = json.loads(content)

        # Extract OSV ID (required field)
        osv_id = osv_data.get("id", "")
        if not osv_id:
            logger.error(f"OSV file {path} missing required 'id' field")
            return [[], [], [], [], [], []]

        # Schema version (required, defaults to 1.0.0 for older entries)
        schema_version = osv_data.get("schema_version", "1.0.0")

        # Modified timestamp (required in OSV schema)
        modified = osv_data.get("modified", None)
        if not modified:
            logger.error(f"OSV file {path} missing required 'modified' field")
            return [[], [], [], [], [], []]

        # Published timestamp (optional)
        published = osv_data.get("published", None)

        # Withdrawn timestamp (optional)
        withdrawn = osv_data.get("withdrawn", None)

        # Summary (optional)
        summary = osv_data.get("summary", None)

        # Details (optional, can be long text)
        details = osv_data.get("details", None)

        # Database-specific data (optional JSONB)
        database_specific = None
        if "database_specific" in osv_data:
            database_specific = Json(osv_data["database_specific"])

        # Add main vulnerability record
        data_vuln.append(
            (
                osv_id,
                schema_version,
                modified,
                published,
                withdrawn,
                summary,
                details,
                database_specific,
            )
        )

        # Parse aliases (including CVE IDs for NVD correlation)
        if "aliases" in osv_data:
            for alias in osv_data["aliases"]:
                data_aliases.append((osv_id, alias))

        # Parse references
        if "references" in osv_data:
            for ref in osv_data["references"]:
                ref_type = ref.get(
                    "type", "WEB"
                )  # Default to WEB if type not specified
                url = ref.get("url", "")
                if url:  # Only add if URL is present
                    data_refs.append((osv_id, ref_type, url))

        # Parse severity scores
        if "severity" in osv_data:
            for sev in osv_data["severity"]:
                severity_type = sev.get("type", "")
                score = sev.get("score", "")
                if severity_type and score:
                    data_severity.append((osv_id, severity_type, score))

        # Parse affected packages
        if "affected" in osv_data:
            for affected in osv_data["affected"]:
                package = affected.get("package", {})
                package_ecosystem = package.get("ecosystem", "")
                package_name = package.get("name", "")
                package_purl = package.get("purl", None)

                # Ranges (JSONB - complex version ranges)
                ranges = None
                if "ranges" in affected:
                    ranges = Json(affected["ranges"])

                # Versions (JSONB - explicit list of affected versions)
                versions = None
                if "versions" in affected:
                    versions = Json(affected["versions"])

                # Ecosystem-specific data
                ecosystem_specific = None
                if "ecosystem_specific" in affected:
                    ecosystem_specific = Json(affected["ecosystem_specific"])

                # Database-specific data (per affected package)
                affected_db_specific = None
                if "database_specific" in affected:
                    affected_db_specific = Json(affected["database_specific"])

                if package_ecosystem and package_name:
                    data_affected.append(
                        (
                            osv_id,
                            package_ecosystem,
                            package_name,
                            package_purl,
                            ranges,
                            versions,
                            ecosystem_specific,
                            affected_db_specific,
                        )
                    )

        # Parse credits
        if "credits" in osv_data:
            for credit in osv_data["credits"]:
                name = credit.get("name", "")
                contact = None
                if "contact" in credit:
                    contact = Json(credit["contact"])
                credit_type = credit.get("type", None)

                if name:  # Only add if name is present
                    data_credits.append((osv_id, name, contact, credit_type))

        logger.debug(
            f"Parsed OSV file: {path} - ID: {osv_id}, "
            f"{len(data_aliases)} aliases, {len(data_refs)} refs, "
            f"{len(data_severity)} severity, {len(data_affected)} affected, "
            f"{len(data_credits)} credits"
        )

    except FileNotFoundError:
        logger.error(f"OSV file not found: {path}")
        return [[], [], [], [], [], []]
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in OSV file {path}: {e}")
        return [[], [], [], [], [], []]
    except Exception as e:
        logger.error(f"Error parsing OSV file {path}: {e}")
        return [[], [], [], [], [], []]

    return [
        data_vuln,
        data_aliases,
        data_refs,
        data_severity,
        data_affected,
        data_credits,
    ]


async def process_all():
    src = await get_all()
    files = await asyncio.to_thread(os.listdir, src)
    for file in files:
        file_path = os.path.join(src, file)
        if file.endswith(".json"):
            parsed_data = await parse_osv_file(file_path)
            # Unpack the 6 data arrays
            (
                data_vuln,
                data_aliases,
                data_refs,
                data_severity,
                data_affected,
                data_credits,
            ) = parsed_data
            # Insert into database
            await c.insert_osv_data(
                data_vuln=data_vuln,
                data_aliases=data_aliases,
                data_refs=data_refs,
                data_severity=data_severity,
                data_affected=data_affected,
                data_credits=data_credits,
            )
    await clean_osv_files("osv/")


async def process_recent():
    """
    Process recently modified OSV vulnerabilities from the modified_id.csv file.

    Workflow:
    1. Download modified_id.csv from OSV GCS bucket
    2. Parse CSV to get list of modified OSV IDs with timestamps
    3. For each ID, check if update is needed (newer than our database)
    4. Download individual OSV JSON files for updates
    5. Parse and update database
    """

    # Download the CSV file with recently modified IDs
    csv_path = await get_recent()

    csv_path_exists = await asyncio.to_thread(os.path.exists, csv_path) if csv_path else False
    if not csv_path or not csv_path_exists:
        logger.error("Failed to download modified_id.csv")
        return

    logger.info(f"Processing recent OSV updates from {csv_path}")

    # Track statistics
    total_entries = 0
    updates_needed = 0
    updates_successful = 0

    try:
        async with aiofiles.open(csv_path, "r") as csvfile:
            content = await csvfile.read()
            # Parse CSV from string
            csv_reader = csv.DictReader(StringIO(content))

            for row in csv_reader:
                total_entries += 1
                osv_id = row.get("id", "").strip()
                csv_modified = row.get("modified", "").strip()

                if not osv_id or not csv_modified:
                    logger.warning(f"Skipping invalid CSV row: {row}")
                    continue

                # Compare the last modified date with our database
                db_record = await c.get_osv_by_id(osv_id)

                needs_update = False
                if db_record and db_record.get("status"):
                    # We have this record, check if CSV version is newer
                    db_modified = db_record["result"].get("modified")
                    if db_modified:
                        # Convert both to datetime for comparison
                        csv_dt = datetime.fromisoformat(
                            csv_modified.replace("Z", "+00:00")
                        )
                        db_dt = (
                            datetime.fromisoformat(db_modified)
                            if isinstance(db_modified, str)
                            else db_modified
                        )

                        if csv_dt > db_dt:
                            needs_update = True
                            logger.debug(
                                f"{osv_id}: CSV modified {csv_modified} > DB modified {db_modified}"
                            )
                    else:
                        needs_update = True  # DB record exists but no modified date
                else:
                    # New record, need to download
                    needs_update = True
                    logger.debug(f"{osv_id}: New record, not in database")

                # If the date from the CSV is newer, download and update
                if needs_update:
                    updates_needed += 1

                    try:
                        # Download individual OSV JSON file
                        # OSV files are stored as: gs://osv-vulnerabilities/<ECOSYSTEM>/<ID>.json
                        # For simplicity, we'll try common ecosystems or use the all/ directory
                        osv_file_path = f"osv/recent/{osv_id}.json"
                        await asyncio.to_thread(os.makedirs, os.path.dirname(osv_file_path), exist_ok=True)

                        # Download from GCS (individual vulnerability files)
                        # The ID format typically includes the ecosystem (e.g., "OSV-2024-001" or "GHSA-xxxx-yyyy-zzzz")
                        downloaded = await download_gcs_bucket(
                            prefix="osv-vulnerabilities",
                            name=f"{osv_id}.json",
                            dst="osv/recent",
                        )

                        downloaded_exists = await asyncio.to_thread(os.path.exists, downloaded) if downloaded else False
                        if downloaded and downloaded_exists:
                            # Parse the OSV JSON file
                            parsed_data = await parse_osv_file(downloaded)

                            # Unpack the 6 data arrays
                            (
                                data_vuln,
                                data_aliases,
                                data_refs,
                                data_severity,
                                data_affected,
                                data_credits,
                            ) = parsed_data

                            # Update the database
                            if data_vuln:
                                result = await c.insert_osv_data(
                                    data_vuln=data_vuln,
                                    data_aliases=data_aliases,
                                    data_refs=data_refs,
                                    data_severity=data_severity,
                                    data_affected=data_affected,
                                    data_credits=data_credits,
                                )

                                if result.get("status"):
                                    updates_successful += 1
                                    logger.info(f"Updated {osv_id} successfully")
                                else:
                                    logger.error(
                                        f"Failed to update {osv_id} in database"
                                    )
                            else:
                                logger.warning(f"No data parsed from {osv_id}")
                        else:
                            logger.error(f"Failed to download {osv_id}.json")

                    except Exception as e:
                        logger.error(f"Error processing {osv_id}: {e}")
                        continue

        logger.info(
            f"Recent updates complete: {total_entries} entries processed, "
            f"{updates_needed} updates needed, {updates_successful} successful"
        )
    except Exception as e:
        logger.error(f"Error processing modified_id.csv: {e}")
    finally:
        await clean_osv_files("osv/recent/")
