import json

from loguru import logger
from datetime import datetime


def grype_parse_report(metadata, path):
    """
    Args:
        path: path to the json grype report
    Returns:
        [] List with the values to be inserted in to the db except for the product, the image name and the image version
    """
    json_data = None
    with open(path, 'r') as f:
        json_data = json.load(f)
    
    ret = []
    for vuln in json_data['matches']:
        v_data = []
        for val in metadata:
            v_data.append(val)

        v_data.append(vuln['vulnerability']['id'])

        fix_versions = ''
        for ver in vuln['vulnerability']['fix']['versions']:
            fix_versions += f"{ver},"
        v_data.append(fix_versions[:-1])

        now = datetime.now().astimezone()
        v_data.append(now) # first seen is now
        v_data.append(now) # last seen is now

        v_data.append(vuln['artifact']['type'])
        v_data.append(vuln['artifact']['name'])
        v_data.append(vuln['artifact']['version'])
        
        locations = ''
        for loc in vuln['artifact']['locations']:
            locations += f"{loc['path']},"
        v_data.append(locations[:-1])

        ret.append(v_data)
    logger.debug(f"A total of {len(ret)} CVEs has been identified when parsing")
    return ret


def grype_get_image_metadata(path):
    """
    Args:
        path: path to the json grype report
    Returns:
        [image_name, image_version]
    """
    json_data = None

    with open(path, 'r') as f:
        json_data = json.load(f)

    logger.debug(f"Distro name: {json_data['distro']['name']}; Distro version: {json_data['distro']['version']}")
    return [json_data['distro']['name'], json_data['distro']['version']]