from pydantic import BaseModel, HttpUrl, Field
from typing import Dict, List, Optional, Union, Any
from enum import Enum

class Severity(str, Enum):
    """Severity levels for findings."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"

class OwaspCategory(str, Enum):
    """OWASP Top 10 2021 categories."""
    A01_BROKEN_ACCESS_CONTROL = "A01:2021 - Broken Access Control"
    A02_CRYPTOGRAPHIC_FAILURES = "A02:2021 - Cryptographic Failures"
    A03_INJECTION = "A03:2021 - Injection"
    A04_INSECURE_DESIGN = "A04:2021 - Insecure Design"
    A05_SECURITY_MISCONFIGURATION = "A05:2021 - Security Misconfiguration"
    A06_VULNERABLE_AND_OUTDATED_COMPONENTS = "A06:2021 - Vulnerable and Outdated Components"
    A07_IDENTIFICATION_AND_AUTHENTICATION_FAILURES = "A07:2021 - Identification and Authentication Failures"
    A08_SOFTWARE_AND_DATA_INTEGRITY_FAILURES = "A08:2021 - Software and Data Integrity Failures"
    A09_SECURITY_LOGGING_AND_MONITORING_FAILURES = "A09:2021 - Security Logging and Monitoring Failures"
    A10_SERVER_SIDE_REQUEST_FORGERY_SSRF = "A10:2021 - Server-Side Request Forgery (SSRF)"
    A03_XSS = "A03:2021 - Cross-Site Scripting (XSS)"
    UNKNOWN = "Unknown" # Added for default if no specific category is matched

class HistoricalScanSummary(BaseModel):
    scan_id: str
    target: str
    start_time: str # Use a string for simplicity, datetime in real app
    status: str # e.g., "completed", "running", "failed"
    finding_count: int
    severity_counts: dict[str, int] # e.g., {"Critical": 2, "High": 5}
    overall_score: float

class ScanInput(BaseModel):
    """Model for representing scan input."""
    target: str = Field(..., description="The target URL to scan.")
    options: Dict[str, object] = Field(default_factory=dict, description="Optional scan parameters.")

# New Pydantic model for the scan start request body
class ScanStartRequest(BaseModel):
    target: str = Field(..., description="The target URL to scan.")
    scan_type: str = Field("full_scan", description="The type of scan to perform. Defaults to 'full_scan'.")
    options: Optional[Dict[str, Any]] = Field(None, description="Optional scan parameters.")

class PluginConfig(BaseModel):
    """Minimal plugin config model for plugin manager compatibility."""
    options: Optional[Dict[str, object]] = None

class ModuleStatus(BaseModel):
    """Status of an individual scanning module."""
    module_name: str
    status: str # e.g., "started", "running", "completed", "failed"
    progress: int = Field(0, ge=0, le=100) # Percentage complete

class RequestLog(BaseModel):
    """Details of an HTTP request."""
    method: str
    url: str
    headers: Optional[Dict[str, str]] = None
    body: Optional[str] = None # Could be bytes, but str for simplicity

class FindingDetails(BaseModel):
    """Additional details about a finding."""
    url: Optional[str] = None
    parameter: Optional[str] = None
    payload: Optional[str] = None
    response_status: Optional[int] = None
    response_body_snippet: Optional[str] = None
    context: Optional[str] = Field(None, description="General context string related to the finding.")

class Finding(BaseModel):
    """Model for representing a security finding."""
    id: str = Field(None, description="Unique ID for the finding.") # For frontend keying, generated in backend
    vulnerability_type: str = Field(..., description="The type of vulnerability found.")
    severity: Severity = Field(..., description="The severity of the vulnerability.")
    description: str = Field(..., description="A brief description of the finding.")
    technical_details: Optional[str] = Field(None, description="Detailed technical information about the finding.")
    remediation: Optional[str] = Field(None, description="Steps to remediate the vulnerability.")
    owasp_category: Optional[OwaspCategory] = Field(None, description="The relevant OWASP Top 10 category.")
    affected_url: Optional[str] = Field(None, description="The URL where the vulnerability was found.")
    request: Optional[RequestLog] = Field(None, description="Example HTTP request that triggered the finding.")
    response: Optional[str] = Field(None, description="Example HTTP response related to the finding.")
    proof: Optional[Union[Dict[str, Any], str]] = Field(None, description="Evidence or proof of the vulnerability.")
    # Added for compatibility with some scanner outputs that might have these fields
    title: Optional[str] = Field(None, description="Title of the finding, if different from vulnerability_type.")
    cwe_id: Optional[str] = Field(None, description="Common Weakness Enumeration (CWE) ID.")
    score: Optional[float] = Field(None, description="Numerical score representing the severity of the finding.")