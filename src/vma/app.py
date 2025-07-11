import logging

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)

_logger = logging.getLogger(__name__)

import vma.nvd as nvd
import vma.connector as c
from vma.routes import init_routes
import argparse
from flask import Flask


def setup_args():
    parser = argparse.ArgumentParser(description="VMA")
    parser.add_argument("-i", "--init", action="store_true", help="Initialize database")
    return parser.parse_args()


def init_server():
    app = Flask(__name__)
    init_routes(app)
    return app


def main():
    args = setup_args()
    try:
        if args.init:
            nvd.init_db()
        else:
            nvd.get_modified_cves()
    except Exception as e:
        _logger.error(e)
        exit(0)


if __name__ == '__main__':
    main()