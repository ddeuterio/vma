import argparse
import requests

from loguru import logger
from fastapi.encoders import jsonable_encoder

import vma.helper as helper
import vma.nvd as nvd
import vma.connector as c
import vma.parser as par


def setup_args():
    parser = argparse.ArgumentParser(description="VMA")
    subparsers = parser.add_subparsers(dest='mode', help='Operation modes')
    nvd_parser = subparsers.add_parser('cve', help='NVD DB mode')
    nvd_parser.add_argument("-i", "--init", action="store_true", help="Initialize database")
    nvd_parser.add_argument("-u", "--update", action="store_true", help="Get updates from NVD")
    create = subparsers.add_parser('create', help='VMA DB create mode')
    create.add_argument("-c", "--choice", choices=['product', 'image'], help="What to insert in the DB")
    create.add_argument("-n", "--name", help="[Image][Product] Name for the image/product")
    create.add_argument("-d", "--description", help="[Image][Product] Description")
    create.add_argument("-v", "--version", help="[Image] Image version")
    create.add_argument("-p", "--product", help="[Image] Product ID to be associated with an image")
    create.add_argument("-f", "--file", help="[Image] File path with vulns to import for an image")
    select = subparsers.add_parser('select', help='VMA DB select mode')
    select.add_argument("-c", "--choice", choices=['product', 'image'], help="What to insert in the DB")
    select.add_argument("-n", "--name", help="[Image][Product] Name for the image/product")
    select.add_argument("-v", "--version", help="[Image] Image version")
    select.add_argument("-p", "--product", help="[Image] Product ID to be associated with an image")
    delete = subparsers.add_parser('delete', help='VMA DB delete mode') # TODO
    importer = subparsers.add_parser('import', help='VMA importer mode')
    importer.add_argument("--port", type=int, default=5000, help="Define the port to run it on")
    importer.add_argument("--host", default='0.0.0.0', help="Define the IP to run it on")
    importer.add_argument("--type", choices=['grype'], help="Scanner type")
    importer.add_argument("--version", choices=['v1'], help="API version to use")
    importer.add_argument("-p", "--product", help="Product id")
    importer.add_argument("-f", "--file", help="File path with vulns to import for an image")
    importer.add_argument("-s", "--secure", action="store_true", help="HTTPS mode")
    importer.add_argument("-t", "--token", help="Authentication token")
    return parser.parse_args()

def main():
    args = setup_args()
    try:
        # nvd mode
        if args.mode == 'cve':
            if args.init:
                nvd.init_db()
            elif args.update:
                nvd.get_modified_cves()
        # create mode
        elif args.mode == 'create':
            if args.choice == 'product':
                c.insert_product((args.name, args.description,))
            elif args.choice == 'image':
                if args.file:
                        image_metadata = par.get_image_metadata(args.file)
                        image_metadata.append(args.product)
                        c.insert_image(image_metadata)
                        data = par.parse_grype_report(image_metadata, args.file)
                        c.insert_image_vulnerabilities(data)
                else:
                    c.insert_image((args.name, args.version, args.product))
        # select mode
        elif args.mode == 'select':
            if args.choice == 'product':
                print(c.get_product((args.name,)))
            else:
                if args.version:
                    print(c.get_image((args.name, args.version, args.product)))
                else:
                    print(c.get_images((args.name, args.product)))
        # importer
        elif args.mode == 'import':
            host, port = helper.validate_input(args.host), args.port
            ttype = helper.validate_input(args.type)
            product = helper.validate_input(args.product)
            file = helper.validate_input(args.file)
            token = helper.validate_input(args.token)
            sec = args.secure
            api_ver = args.version

            url = "http"
            if sec:
                url += "s"
            url += f"://{host}:{port}/api/{api_ver}/import"
            payload = None

            if ttype == 'grype':
                image_metadata = par.grype_get_image_metadata(file)
                image_metadata.append(product)
                data = par.grype_parse_report(image_metadata, file)
                payload = {
                    'scanner': ttype,
                    'product': product,
                    'image': image_metadata[0],
                    'version': image_metadata[1],
                    'data': jsonable_encoder(data)
                }
            res = requests.post(url=url, json=payload)
            res_json = res.json()
            if res_json['status'] and res_json['result']['num_cve'] == len(data):
                logger.info("Import was successfull.")
            else:
                logger.error("Import failed.")
    except Exception as e:
        logger.error(e)
        exit(0)


if __name__ == '__main__':
    helper.configure_logging('DEBUG')
    main()