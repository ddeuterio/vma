from typing import List, Dict, Optional
from pydantic import BaseModel


# =============================================================================
# Universal SCA (Software Composition Analysis) Format
# =============================================================================

class CvssScore(BaseModel):
    """CVSS score from any source (NVD, vendor, etc.)"""
    source: str  # "nvd@nist.gov", "cve@mitre.org", etc.
    type: str  # "Primary", "Secondary"
    version: str  # "2.0", "3.0", "3.1", "4.0"
    vector: str  # Full vector string
    base_score: float
    exploitability_score: Optional[float] = None
    impact_score: Optional[float] = None


class EpssScore(BaseModel):
    """EPSS (Exploit Prediction Scoring System) data"""
    cve: str
    epss: float  # Probability 0-1
    percentile: float  # Percentile ranking
    date: str


class CweEntry(BaseModel):
    """CWE (Common Weakness Enumeration) entry"""
    cwe: str  # "CWE-787"
    source: Optional[str] = None
    type: str = "Primary"


class FixInfo(BaseModel):
    """Fix/remediation information"""
    versions: List[str] = []
    state: str = ""  # "fixed", "wontfix", "not-fixed", ""
    suggested_version: Optional[str] = None


class ArtifactLocation(BaseModel):
    """Location of an artifact within the container image"""
    path: str
    layer_id: Optional[str] = None


class MatchDetail(BaseModel):
    """Details about how the vulnerability was matched"""
    type: str  # "cpe-match", "exact-direct-match", "exact-indirect-match"
    matcher: Optional[str] = None
    confidence: Optional[str] = None
    searched_by: Optional[Dict] = None
    found: Optional[Dict] = None


class SeverityInfo(BaseModel):
    """Combined severity information"""
    level: str  # Critical, High, Medium, Low, Negligible, Unknown
    cvss: List[CvssScore] = []
    epss: List[EpssScore] = []
    risk_score: Optional[float] = None  # Scanner's composite risk score


class VulnerabilityScaUniversal(BaseModel):
    """Universal format for SCA vulnerability findings.

    Designed to capture all relevant data from any SCA scanner (Grype, Trivy, etc.)
    while providing a consistent structure for storage and analysis.
    """
    # Identification
    vuln_id: str  # CVE ID or other vulnerability identifier
    source: str  # Data source URL
    namespace: Optional[str] = None  # e.g., "nvd:cpe", "alpine:distro:alpine:3.19"

    # Core vulnerability data
    description: str = ""
    severity: SeverityInfo
    urls: List[str] = []
    cwes: List[CweEntry] = []

    # Artifact (affected package) information
    affected_component: str  # Package name
    affected_version: str  # Package version
    affected_component_type: str  # "apk", "deb", "rpm", "npm", "pip", etc.
    affected_path: str  # Comma-separated paths (legacy compatibility)
    purl: Optional[str] = None  # Package URL (universal package identifier)
    cpes: List[str] = []  # Common Platform Enumeration identifiers
    licenses: List[str] = []  # Package licenses
    locations: List[ArtifactLocation] = []  # Detailed location info with layer IDs
    upstreams: List[str] = []  # Upstream package names

    # Fix & match context
    fix: FixInfo
    match_details: List[MatchDetail] = []
    related_vulnerabilities: List[str] = []


# =============================================================================
# SCA Report Models
# =============================================================================

class ScaReport(BaseModel):
    """SCA scan report container with universal vulnerability format"""
    scanner: str
    image_name: str
    image_version: str
    product: str
    team: str
    vulnerabilities: List[VulnerabilityScaUniversal]


# =============================================================================
# SAST (Static Application Security Testing) Models
# =============================================================================

class SeveritySast(BaseModel):
    severity: str
    confidence: Optional[str] = None
    impact: Optional[str] = None
    likelihood: Optional[str] = None


class VulnerabilitySast(BaseModel):
    rule_id: str
    file_path: str
    start_line: int
    start_col: int
    end_line: int
    end_col: int
    message: Optional[str] = None
    severity: str
    confidence: Optional[str] = None
    code_snippet: Optional[str] = None
    suggested_fix: Optional[str] = None
    fingerprint: Optional[str] = None
    cwes: List[Dict] = []
    owasp: List[str] = []
    refs: List[str] = []
    category: Optional[str] = None
    subcategory: List[str] = []
    technology: List[str] = []
    vulnerability_class: List[str] = []
    impact: Optional[str] = None
    likelihood: Optional[str] = None
    engine_kind: Optional[str] = None
    validation_state: Optional[str] = None


class SastReport(BaseModel):
    scanner: str
    product: str
    team: str
    findings: List[VulnerabilitySast]
