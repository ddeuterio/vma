import json
import aiofiles
from loguru import logger
from datetime import datetime


async def grype_parser(path: str) -> list:
    pass
    json_data = None
    async with aiofiles.open(path, "r") as f:
        content = await f.read()
        json_data = json.loads(content)

    ret = []
    for vuln in json_data["matches"]:
        vuln_sca = {}
        severity = (
            vuln["vulnerability"]["severity"]
            if "severity" in vuln["vulnerability"]
            else ""
        )
        cvss = vuln["vulnerability"]["cvss"] if "cvss" in vuln["vulnerability"] else []
        epss = vuln["vulnerability"]["epss"] if "epss" in vuln["vulnerability"] else []
        vuln_sca["severity"] = {"value": severity, "cvss": cvss, "epss": epss}
        vuln_sca["id"] = (
            vuln["vulnerability"]["id"] if "id" in vuln["vulnerability"] else ""
        )
        vuln_sca["source"] = (
            vuln["vulnerability"]["dataSource"]
            if "dataSource" in vuln["vulnerability"]
            else ""
        )
        vuln_sca["urls"] = (
            vuln["vulnerability"]["urls"] if "urls" in vuln["vulnerability"] else []
        )
        vuln_sca["description"] = (
            vuln["vulnerability"]["description"]
            if "description" in vuln["vulnerability"]
            else ""
        )
        vuln_sca["cwes"] = (
            vuln["vulnerability"]["cwes"] if "cwes" in vuln["vulnerability"] else [{}]
        )
        vuln_sca["fix"] = (
            vuln["vulnerability"]["fix"] if "fix" in vuln["vulnerability"] else {}
        )
        vuln_sca["related_vulnerabilities"] = (
            vuln["relatedVulnerabilities"]
            if "relatedVulnerabilities" in vuln["vulnerability"]
            else []
        )

        # Extract artifact data
        vuln_sca["affected_component_type"] = (
            vuln["artifact"]["type"] if "type" in vuln["artifact"] else ""
        )
        vuln_sca["affected_component"] = (
            vuln["artifact"]["name"] if "name" in vuln["artifact"] else ""
        )
        vuln_sca["affected_version"] = (
            vuln["artifact"]["version"] if "version" in vuln["artifact"] else ""
        )
        locations = ""
        if "locations" in vuln["artifact"]:
            for loc in vuln["artifact"]["locations"]:
                locations += f"{loc['path']},"
            locations = locations[:-1] if locations else ""
        vuln_sca["affected_path"] = locations

        ret.append(vuln_sca)
    logger.debug(f"A total of {len(ret)} CVEs has been identified when parsing")
    return ret


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


def _parse_semgrep_cwes(raw_cwes: list) -> list:
    """Parse CWE strings like 'CWE-89: SQL Injection' into structured dicts."""
    parsed = []
    for cwe in raw_cwes:
        if isinstance(cwe, str) and ":" in cwe:
            parts = cwe.split(":", 1)
            parsed.append({"id": parts[0].strip(), "name": parts[1].strip()})
        elif isinstance(cwe, str):
            parsed.append({"id": cwe.strip(), "name": ""})
        else:
            parsed.append(cwe)
    return parsed


async def semgrep_parser(path: str) -> list:
    """
    Parse Semgrep JSON output into a list of finding dicts.

    Args:
        path: path to the Semgrep JSON report

    Returns:
        List of finding dicts ready for DB insertion
    """
    json_data = None
    async with aiofiles.open(path, "r") as f:
        content = await f.read()
        json_data = json.loads(content)

    ret = []
    for result in json_data.get("results", []):
        finding = {}
        finding["rule_id"] = result.get("check_id", "")
        finding["file_path"] = result.get("path", "")

        start = result.get("start", {})
        finding["start_line"] = start.get("line", 0)
        finding["start_col"] = start.get("col", 0)

        end = result.get("end", {})
        finding["end_line"] = end.get("line", 0)
        finding["end_col"] = end.get("col", 0)

        extra = result.get("extra", {})
        finding["message"] = extra.get("message", "")
        finding["severity"] = extra.get("severity", "")
        finding["code_snippet"] = extra.get("lines", "")
        finding["suggested_fix"] = extra.get("fix", "")
        finding["fingerprint"] = extra.get("fingerprint", "")
        finding["validation_state"] = extra.get("validation_state", "")
        finding["engine_kind"] = extra.get("engine_kind", "")

        metadata = extra.get("metadata", {})
        finding["confidence"] = metadata.get("confidence", "")
        finding["category"] = metadata.get("category", "")
        finding["impact"] = metadata.get("impact", "")
        finding["likelihood"] = metadata.get("likelihood", "")
        finding["cwes"] = _parse_semgrep_cwes(metadata.get("cwe", []))
        finding["owasp"] = metadata.get("owasp", [])
        finding["refs"] = metadata.get("references", [])
        finding["subcategory"] = metadata.get("subcategory", [])
        finding["technology"] = metadata.get("technology", [])
        finding["vulnerability_class"] = metadata.get("vulnerability_class", [])

        ret.append(finding)

    logger.debug(f"A total of {len(ret)} SAST findings identified when parsing Semgrep report")
    return ret
