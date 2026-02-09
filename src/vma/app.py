import argparse
import logging
import asyncio
import httpx
import os

from loguru import logger
from dotenv import dotenv_values

import vma.helper as helper
import vma.nvd as nvd
import vma.osv as osv
import vma.parser as par
import vma.connector as c
import vma.auth as a


def setup_args():
    parser = argparse.ArgumentParser(description="VMA")
    subparsers = parser.add_subparsers(dest="mode", help="Operation modes")
    nvd_parser = subparsers.add_parser("cve", help="NVD DB mode")
    nvd_parser.add_argument(
        "-i", "--init", action="store_true", help="Initialize database"
    )
    nvd_parser.add_argument(
        "-u", "--update", action="store_true", help="Get updates from NVD"
    )
    osv_parser = subparsers.add_parser("osv", help="OSV database mode")
    osv_parser.add_argument(
        "-a", "--all", action="store_true", help="Download and process all OSV data"
    )
    osv_parser.add_argument(
        "-r",
        "--recent",
        action="store_true",
        help="Process only recently modified OSV entries",
    )
    importer = subparsers.add_parser("import", help="VMA importer mode")
    importer.add_argument(
        "--port", type=int, default=5000, help="Define the port to run it on"
    )
    importer.add_argument(
        "--host", default="0.0.0.0", help="Define the IP to run it on"
    )
    importer.add_argument("--type", choices=["sca", "sast"], help="Scanner type")
    importer.add_argument(
        "--scanner", choices=["grype", "semgrep"], help="Scanner option"
    )
    importer.add_argument(
        "--api-version", choices=["v1"], default="v1", help="API version to use"
    )
    importer.add_argument("--repo", help="Repository name")
    importer.add_argument("--product", help="Product ID")
    importer.add_argument("--image", help="Image ID")
    importer.add_argument("--version", help="Image version")
    importer.add_argument("--team", help="Team ID")
    importer.add_argument("--file", help="File path with vulns to import for an image")
    importer.add_argument("--secure", action="store_true", help="HTTPS mode")
    importer.add_argument("--token", help="Authentication token")
    importer.add_argument(
        "--ignore-cert",
        action="store_true",
        help="Ignore self-signed certificate warning",
    )
    importer.add_argument(
        "--env-file",
        help="Path to env file with import parameters",
    )
    login = subparsers.add_parser("login", help="Initialize users")
    login.add_argument("--init", action="store_true", help="init users")
    return parser.parse_args()


async def main():
    args = setup_args()
    try:
        # nvd mode
        if args.mode == "cve":
            if args.init:
                await nvd.init_db()
            elif args.update:
                await nvd.get_modified_cves()
        # osv mode
        elif args.mode == "osv":
            if args.all:
                logger.info("Starting OSV full database download and processing...")
                await osv.process_all()
                logger.info("OSV full database processing complete")
            elif args.recent:
                logger.info("Starting OSV recent updates processing...")
                await osv.process_recent()
                logger.info("OSV recent updates processing complete")
            else:
                logger.error("Please specify --all or --recent for OSV mode")
        # importer
        elif args.mode == "import":
            _apply_import_env(args)
            file = helper.validate_input(args.file)
            token = helper.validate_input(args.token)

            if not file:
                logger.error("File path is required for import")
                return 1
            if not token:
                logger.error("Authentication token is required for import")
                return 1

            url = "http"
            if args.secure:
                url += "s"
            url += (
                f"://{args.host}:{args.port}/api/{args.api_version}/import/{args.type}"
            )

            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            }
            payload = None

            if args.scanner == "grype":
                product = helper.validate_input(args.product)
                image = helper.validate_input(args.image)
                version = helper.validate_input(args.version)
                team = helper.validate_input(args.team)
                if not product or not image or not version or not team:
                    logger.error("Product, image, version, and team are required for grype import")
                    return 1
                data = await par.grype_parser(path=file)
                payload = {
                    "scanner": args.scanner,
                    "product": product,
                    "image_name": image,
                    "image_version": version,
                    "team": team,
                    "vulnerabilities": data,
                }
            elif args.scanner == "semgrep":
                repo = helper.validate_input(args.repo)
                product = helper.validate_input(args.product)
                team = helper.validate_input(args.team)
                if not repo or not product or not team:
                    logger.error("Repository, product, and team are required for semgrep import")
                    return 1
                data = await par.semgrep_parser(path=file)
                payload = {
                    "scanner": args.scanner,
                    "repository": repo,
                    "product": product,
                    "team": team,
                    "findings": data,
                }
            else:
                logger.debug("Invalid scanner given by parameter")
                return 1

            verify_ssl = not args.ignore_cert if hasattr(args, "ignore_cert") else True
            async with httpx.AsyncClient(verify=verify_ssl) as client:
                res = await client.post(
                    url=url,
                    json=payload,
                    headers=headers,
                )
                res_json = res.json()
            if res_json["status"]:
                logger.info("Import was successfull.")
            else:
                logger.error("Import failed.")
        elif args.mode == "login":
            if args.init:
                await c.insert_teams(name="admin", description="Admin team")
                await c.insert_users(
                    email="admin@vma.com",
                    password=a.hasher.hash("changeme"),
                    name="admin",
                    scopes={"admin": "admin"},
                    is_root=True,
                )
    except Exception as e:
        logger.error(e)
        exit(0)


def _coerce_bool(value: str) -> bool:
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def _apply_import_env(args) -> None:
    if not getattr(args, "env_file", None):
        return

    env_path = helper.validate_input(args.env_file)
    if not env_path or not os.path.exists(env_path):
        logger.error(f"Import env file not found: {args.env_file}")
        return

    env_data = dotenv_values(env_path)
    normalized = {
        (key or "").strip().upper(): value for key, value in env_data.items() if key
    }

    def get_value(*keys):
        for key in keys:
            value = normalized.get(key)
            if value is not None and value != "":
                return value
        return None

    port = get_value("VMA_PORT", "PORT")
    if port and args.port == 5000:
        args.port = int(port)

    host = get_value("VMA_HOST", "HOST")
    if host and args.host == "0.0.0.0":
        args.host = host

    api_version = get_value("VMA_API_VERSION", "API_VERSION", "API-VERSION")
    if api_version and args.api_version == "v1":
        args.api_version = api_version

    scan_type = get_value("VMA_TYPE", "TYPE")
    if scan_type and not args.type:
        args.type = scan_type

    scanner = get_value("VMA_SCANNER", "SCANNER")
    if scanner and not args.scanner:
        args.scanner = scanner

    repo = get_value("VMA_REPO", "REPO", "REPOSITORY")
    if repo and not args.repo:
        args.repo = repo

    product = get_value("VMA_PRODUCT", "PRODUCT")
    if product and not args.product:
        args.product = product

    image = get_value("VMA_IMAGE", "IMAGE", "IMAGE_NAME")
    if image and not args.image:
        args.image = image

    version = get_value("VMA_VERSION", "VERSION", "IMAGE_VERSION")
    if version and not args.version:
        args.version = version

    team = get_value("VMA_TEAM", "TEAM")
    if team and not args.team:
        args.team = team

    file_path = get_value("VMA_FILE", "FILE", "PATH")
    if file_path and not args.file:
        args.file = file_path

    token = get_value("VMA_TOKEN", "TOKEN")
    if token and not args.token:
        args.token = token

    secure = get_value("VMA_SECURE", "SECURE")
    if secure is not None and not args.secure:
        args.secure = _coerce_bool(secure)

    ignore_cert = get_value("VMA_IGNORE_CERT", "IGNORE_CERT", "IGNORE-CERT")
    if ignore_cert is not None and not args.ignore_cert:
        args.ignore_cert = _coerce_bool(ignore_cert)


def cli():
    """Synchronous entry point for CLI."""
    helper.configure_logging(logging.DEBUG)
    asyncio.run(main())


if __name__ == "__main__":
    cli()
