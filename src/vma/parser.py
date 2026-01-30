import json
import aiofiles
from loguru import logger
from datetime import datetime


def _parse_cvss_scores(cvss_list: list) -> list:
    """Parse CVSS scores from Grype format to universal format."""
    parsed = []
    for cvss in cvss_list:
        if not isinstance(cvss, dict):
            continue
        metrics = cvss.get("metrics", {})
        parsed.append({
            "source": cvss.get("source", ""),
            "type": cvss.get("type", ""),
            "version": cvss.get("version", ""),
            "vector": cvss.get("vector", ""),
            "base_score": metrics.get("baseScore", 0.0),
            "exploitability_score": metrics.get("exploitabilityScore"),
            "impact_score": metrics.get("impactScore"),
        })
    return parsed


def _parse_epss_scores(epss_list: list) -> list:
    """Parse EPSS scores from Grype format to universal format."""
    parsed = []
    for epss in epss_list:
        if not isinstance(epss, dict):
            continue
        parsed.append({
            "cve": epss.get("cve", ""),
            "epss": epss.get("epss", 0.0),
            "percentile": epss.get("percentile", 0.0),
            "date": epss.get("date", ""),
        })
    return parsed


def _parse_cwes(cwe_list: list) -> list:
    """Parse CWE entries from Grype format to universal format."""
    parsed = []
    for cwe in cwe_list:
        if not isinstance(cwe, dict):
            continue
        parsed.append({
            "cwe": cwe.get("cwe", ""),
            "source": cwe.get("source"),
            "type": cwe.get("type", "Primary"),
        })
    return parsed


def _parse_fix_info(fix_data: dict, match_details: list) -> dict:
    """Parse fix information, including suggested version from match details."""
    if not isinstance(fix_data, dict):
        return {"versions": [], "state": "", "suggested_version": None}

    # Look for suggested version in match details
    suggested_version = None
    for match in match_details:
        if isinstance(match, dict) and "fix" in match:
            suggested = match.get("fix", {}).get("suggestedVersion")
            if suggested:
                suggested_version = suggested
                break

    return {
        "versions": fix_data.get("versions", []),
        "state": fix_data.get("state", ""),
        "suggested_version": suggested_version,
    }


def _parse_locations(locations_list: list) -> tuple[str, list]:
    """Parse artifact locations, extracting both legacy path string and detailed locations.

    Returns:
        Tuple of (legacy_path_string, detailed_locations_list)
    """
    legacy_paths = []
    detailed = []

    for loc in locations_list:
        if not isinstance(loc, dict):
            continue
        path = loc.get("path", "")
        if path:
            legacy_paths.append(path)
        detailed.append({
            "path": path,
            "layer_id": loc.get("layerID"),
        })

    return ",".join(legacy_paths), detailed


def _parse_match_details(match_details_list: list) -> list:
    """Parse match details from Grype format."""
    parsed = []
    for match in match_details_list:
        if not isinstance(match, dict):
            continue
        parsed.append({
            "type": match.get("type", ""),
            "matcher": match.get("matcher"),
            "confidence": match.get("confidence"),
            "searched_by": match.get("searchedBy"),
            "found": match.get("found"),
        })
    return parsed


def _parse_upstreams(upstreams_list: list) -> list:
    """Extract upstream package names."""
    names = []
    for upstream in upstreams_list:
        if isinstance(upstream, dict):
            name = upstream.get("name")
            if name:
                names.append(name)
        elif isinstance(upstream, str):
            names.append(upstream)
    return names


def _parse_related_vulnerabilities(related_list: list) -> list:
    """Extract related vulnerability IDs."""
    ids = []
    for related in related_list:
        if isinstance(related, dict):
            vid = related.get("id")
            if vid:
                ids.append(vid)
        elif isinstance(related, str):
            ids.append(related)
    return ids


async def grype_parser(path: str) -> list:
    """Parse Grype JSON output into universal SCA vulnerability format.

    Extracts all available fields from Grype including:
    - Core vulnerability data (ID, severity, description, CVSS, EPSS)
    - Artifact details (name, version, type, PURL, CPEs, licenses)
    - Location info (paths and container layer IDs)
    - Match context (how the vulnerability was matched)
    - Fix information (available versions, suggested fixes)

    Args:
        path: Path to the Grype JSON report file

    Returns:
        List of vulnerability dicts in universal format
    """
    json_data = None
    async with aiofiles.open(path, "r") as f:
        content = await f.read()
        json_data = json.loads(content)

    ret = []
    for match in json_data.get("matches", []):
        vuln = match.get("vulnerability", {})
        artifact = match.get("artifact", {})
        match_details_raw = match.get("matchDetails", [])

        # Parse severity components
        cvss_scores = _parse_cvss_scores(vuln.get("cvss", []))
        epss_scores = _parse_epss_scores(vuln.get("epss", []))
        risk_score = vuln.get("risk")

        # Parse locations (both legacy format and detailed)
        legacy_path, detailed_locations = _parse_locations(artifact.get("locations", []))

        # Parse match details (needed for suggested fix version)
        match_details = _parse_match_details(match_details_raw)

        # Build universal vulnerability dict
        vuln_sca = {
            # Identification
            "vuln_id": vuln.get("id", ""),
            "source": vuln.get("dataSource", ""),
            "namespace": vuln.get("namespace"),

            # Core vulnerability data
            "description": vuln.get("description", ""),
            "severity": {
                "level": vuln.get("severity", "Unknown"),
                "cvss": cvss_scores,
                "epss": epss_scores,
                "risk_score": risk_score,
            },
            "urls": vuln.get("urls", []),
            "cwes": _parse_cwes(vuln.get("cwes", [])),

            # Artifact information
            "affected_component": artifact.get("name", ""),
            "affected_version": artifact.get("version", ""),
            "affected_component_type": artifact.get("type", ""),
            "affected_path": legacy_path,
            "purl": artifact.get("purl"),
            "cpes": artifact.get("cpes", []),
            "licenses": artifact.get("licenses", []),
            "locations": detailed_locations,
            "upstreams": _parse_upstreams(artifact.get("upstreams", [])),

            # Fix & match context
            "fix": _parse_fix_info(vuln.get("fix", {}), match_details_raw),
            "match_details": match_details,
            "related_vulnerabilities": _parse_related_vulnerabilities(
                match.get("relatedVulnerabilities", [])
            ),
        }

        ret.append(vuln_sca)

    logger.debug(f"Parsed {len(ret)} SCA vulnerabilities from Grype report")
    return ret


async def grype_get_image_metadata(path):
    """Extract image metadata from Grype report.

    Args:
        path: Path to the JSON grype report

    Returns:
        [image_name, image_version] or distro info if available
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
    """Parse JFrog Xray report format."""
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
    """Parse Semgrep JSON output into a list of finding dicts.

    Args:
        path: Path to the Semgrep JSON report

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
