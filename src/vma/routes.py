from flask import render_template, request
from vma import connector as c
import logging

_logger = logging.getLogger(__name__)

SERVER_PATH = 'server/'

def init_routes(app):
    @app.route('/')
    def index():
        return render_template('index.html')

    @app.route('/search')
    def search():
        """
        Function called by JS code in the web UI to get the results wanted
        """
        query = request.args.get('q')
        values = [(query,)]
        res = []
        try:
            res = c.get_vulnerabilities(values)
        except Exception as e:
            _logger.error(f"error fetching data from the db: {e}")

        return res