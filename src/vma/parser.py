import json

import aiofiles
from loguru import logger
from datetime import datetime


async def grype_parse_report(metadata, path):
    """
    Only supports json type atm
    Args:
        path: path to the json grype report
    Returns:
        [] List with the values to be inserted in to the db except for the product, the image name and the image version
    """
    json_data = None
    async with aiofiles.open(path, "r") as f:
        content = await f.read()
        json_data = json.loads(content)

    ret = []
    for vuln in json_data["matches"]:
        v_data = []
        for val in metadata:
            v_data.append(val)
        v_data.append(vuln["vulnerability"]["id"])

        fix_versions = ""
        for ver in vuln["vulnerability"]["fix"]["versions"]:
            fix_versions += f"{ver},"
        v_data.append(fix_versions[:-1])

        now = datetime.now().astimezone().isoformat()
        v_data.append(now)  # first seen is now
        v_data.append(now)  # last seen is now

        v_data.append(vuln["artifact"]["type"])
        v_data.append(vuln["artifact"]["name"])
        v_data.append(vuln["artifact"]["version"])

        locations = ""
        for loc in vuln["artifact"]["locations"]:
            locations += f"{loc['path']},"
        v_data.append(locations[:-1])
        ret.append(v_data)
    logger.debug(f"A total of {len(ret)} CVEs has been identified when parsing")
    return ret


async def grype_get_image_metadata(path):
    """
    Args:
        path: path to the json grype report
    Returns:
        [image_name, image_version]
    """
    json_data = None

    async with aiofiles.open(path, "r") as f:
        content = await f.read()
        json_data = json.loads(content)

    logger.debug(
        f"Distro name: {json_data['distro']['name']}; Distro version: {json_data['distro']['version']}"
    )
    return [json_data["distro"]["name"], json_data["distro"]["version"]]


async def xray_parse_report(metadata, path):
    # TODO add the metadata
    async with aiofiles.open(path, "r") as f:
        content = await f.read()
        data = json.loads(content)

    r_data = []
    for r in data:
        if "vulnerabilities" in r:
            for v in r["vulnerabilities"]:
                all_v_keys = v.keys()
                for key_comp in v["components"].keys():
                    row = dict()
                    row["scan_id"] = r["scan_id"]
                    row["component_id"] = r["component_id"]
                    row["severity"] = v["severity"]
                    row["component"] = key_comp
                    row["current_version"] = key_comp.split(":")[-1]
                    row["fix_versions"] = ""
                    if "fixed_veresions" in v["components"][key_comp].keys():
                        fx_ver = []
                        for ver in v["components"][key_comp]["fixed_versions"]:
                            fx_ver.append(ver.strip("[]"))
                        row["fix_versions"] = ", ".join(fx_ver)
                    if "impact_paths" in v["components"][key_comp].keys():
                        imp = []
                        for fsttier in v["components"][key_comp]["impact_paths"]:
                            for val in fsttier:
                                if "full_path" in val.keys():
                                    imp.append(val["full_path"])
                        row["impact_paths"] = ", ".join(imp)
                    row["issue_id"] = v["issue_id"]
                    row["references"] = ""
                    if "references" in all_v_keys:
                        row["references"] = ", ".join(v["references"])
                    if "cves" in all_v_keys:
                        for cve in v["cves"]:
                            for key in cve.keys():
                                if key == "cwe_details":
                                    continue
                                elif key == "cwe":
                                    row["cwe"] = ", ".join(cve[key])
                                else:
                                    row[key] = cve[key]
                    row["package_type"] = r["package_type"]
                    row["status"] = r["status"]
                    row["summary"] = r["summary"]
                    r_data += [row]
            logger.debug(f"xray_parse_report; {len(r_data)} vulnerabilities parsed")
        else:
            logger.debug("xray_parse_report; no vulnerabilities parsed")
        return r_data
