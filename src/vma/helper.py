import sys
import logging
from loguru import logger

errors = {
    "400": "One or several parameters are missing or malformed",
    "401": "User is not authorized to perform this action",
    "500": "Error procesing data",
    "invalid_token_format": "Invalid token format",
}


class InterceptHandler(logging.Handler):
    """
    Default handler from examples in loguru documentaion.
    See https://loguru.readthedocs.io/en/stable/overview.html#entirely-compatible-with-standard-logging
    """

    def emit(self, record):
        # Get corresponding Loguru level if it exists
        try:
            level = logger.level(record.levelname).name
        except ValueError:
            level = record.levelno

        # Find caller from where originated the logged message
        frame, depth = logging.currentframe(), 6
        while frame.f_code.co_filename == logging.__file__:  # type: ignore[arg-type]
            frame = frame.f_back  # type: ignore[arg-type]
            depth += 1

        logger.opt(depth=depth, exception=record.exc_info).log(
            level, record.getMessage()
        )


def configure_logging(level: int, uvicorn: bool = False):
    logging.basicConfig(handlers=[InterceptHandler()], level=0, force=True)
    if uvicorn:
        for name in ["uvicorn", "uvicorn.error", "uvicorn.access"]:
            logging.getLogger(name).handlers = [InterceptHandler()]
            logging.getLogger(name).propagate = False
    logger.remove()
    log_format = "{time} | {level} | {name} | {function}:{line} |  {message}"
    logger.add(sys.stderr, level=level, enqueue=True, format=log_format)
    logger.add(
        "vma.log", level=level, enqueue=True, format=log_format, rotation="500 MB"
    )
    configure_logging._configured = True  # type: ignore[args-type]


def format_vulnerability_rows(rows: list) -> list:
    """
    Convert tuples returned by the connector into dictionaries that are easier
    to render in the templates.

    Args:
        rows: [tuples()]
    Returns:
        []
    """
    formatted = []
    for row in rows:
        base_score = row[8]
        base_severity = row[9]
        cvss_version = row[10]

        first_seen = row[6].strftime("%Y-%m-%d") if row[6] else None
        last_seen = row[7].strftime("%Y-%m-%d") if row[7] else None

        formatted.append(
            {
                "cve": row[0],
                "fix_versions": row[1],
                "component_type": row[2],
                "component": row[3],
                "component_version": row[4],
                "component_path": row[5],
                "first_seen": first_seen,
                "last_seen": last_seen,
                "cvss": {
                    "score": base_score,
                    "severity": base_severity,
                    "version": cvss_version,
                }
                if base_score is not None
                else None,
            }
        )
    return formatted


def normalize_comparison(comp: list) -> dict:
    """
    Convert list of tuples into a list of dict

    Args:
        comp: [tuples()]
    Returns
        [dict()]
    """
    stats = {"shared": 0, "only_version_a": 0, "only_version_b": 0}
    if not comp:
        return {"stats": stats, "comparison": []}

    ret = []
    for row in comp:
        if not row:
            continue
        (
            vuln_id,
            severity_level,
            comparison,
            affected_component_type,
            affected_component,
            affected_path,
            cvss,
            epss,
            urls,
            cwes,
            fix,
        ) = row[:11]

        ret.append(
            {
                "vuln_id": vuln_id,
                "severity_level": severity_level,
                "comparison": comparison,
                "affected_component_type": affected_component_type,
                "affected_component": affected_component,
                "affected_path": affected_path,
                "cvss": cvss,
                "epss": epss,
                "urls": urls,
                "cwes": cwes,
                "fix": fix,
            }
        )

        if comparison in stats:
            stats[comparison] += 1

    return {"stats": stats, "comparison": ret}


def escape_like(s: str, escape_char: str = "\\") -> str:
    # Escape backslash first, then % and _
    s = s.replace(escape_char, escape_char * 2)
    s = s.replace("%", escape_char + "%")
    s = s.replace("_", escape_char + "_")
    return s


def validate_input(data: str) -> str | None:
    if not data:
        return None

    return str(data.strip())


def validate_scopes(data: str) -> dict | None:
    if not data:
        return None

    ret = {}
    t = data.split(",")
    for s in t:
        aux = s.split(":")
        ret[aux[0]] = aux[1]

    return ret
