import argparse
import logging
import asyncio
import httpx

from loguru import logger

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
    importer.add_argument("--type", choices=["grype"], help="Scanner type")
    importer.add_argument(
        "--api-version", choices=["v1"], default="v1", help="API version to use"
    )
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
            file = helper.validate_input(args.file)
            token = helper.validate_input(args.token)

            url = "http"
            if args.secure:
                url += "s"
            url += f"://{args.host}:{args.port}/api/{args.api_version}/import"
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            }
            payload = None

            if args.type == "grype":
                # image_metadata = par.grype_get_image_metadata(file)
                image_metadata = [
                    args.type,
                    args.image,
                    args.version,
                    args.product,
                    args.team,
                ]
                data = await par.grype_parse_report(image_metadata, file)
                payload = {
                    "scanner": args.type,
                    "product": args.product,
                    "image": args.image,
                    "version": args.version,
                    "team": args.team,
                    "data": data,
                }
            async with httpx.AsyncClient() as client:
                res = await client.post(
                    url=url,
                    json=payload,
                    headers=headers,
                    verify=(not args.ignore_cert)
                    if hasattr(args, "ignore_cert")
                    else True,
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


def cli():
    """Synchronous entry point for CLI."""
    helper.configure_logging(logging.DEBUG)
    asyncio.run(main())


if __name__ == "__main__":
    cli()
