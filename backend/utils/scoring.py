from typing import List, Dict, Any

from backend.types.models import Finding, Severity, OwaspCategory


def classify_finding(finding: Finding) -> Finding:
    """
    Classifies a vulnerability finding based on its characteristics and assigns an OWASP category.

    Args:
        finding: The Finding object to classify.

    Returns:
        The Finding object with an updated OWASP category.
    """
    # This is a placeholder for actual classification logic.
    # In a real-world scenario, this would involve analyzing the vulnerability type,
    # description, and technical details to map it to an OWASP category.
    # You might use a mapping, keywords, or more sophisticated analysis.

    if "SQL Injection" in finding.vulnerability_type:
        finding.owasp_category = OwaspCategory.A01_INJECTION
    elif "Cross-Site Scripting" in finding.vulnerability_type:
        finding.owasp_category = OwaspCategory.A03_XSS
    elif "Security Misconfiguration" in finding.vulnerability_type:
        finding.owasp_category = OwaspCategory.A05_SECURITY_MISCONFIGURATION
    elif "Sensitive Data Exposure" in finding.vulnerability_type:
        finding.owasp_category = OwaspCategory.A07_INSECURE_DESERIALIZATION # Using a relevant category
    # Add more classification rules here

    # Default to None if no specific category is matched
    if finding.owasp_category is None:
         finding.owasp_category = OwaspCategory.UNKNOWN


    return finding


def assign_severity_score(finding: Finding) -> Finding:
    """
    Assigns a standardized severity score to a vulnerability finding.

    Args:
        finding: The Finding object to score.

    Returns:
        The Finding object with an updated severity score.
    """
    # This is a placeholder for actual scoring logic.
    # Scoring can be based on various factors like CVSS score, potential impact,
    # ease of exploitation, etc. For this example, we'll use a simple mapping
    # based on the existing Severity enum.

    if finding.severity == Severity.CRITICAL:
        finding.score = 10.0  # Example score
    elif finding.severity == Severity.HIGH:
        finding.score = 8.0   # Example score
    elif finding.severity == Severity.MEDIUM:
        finding.score = 5.0   # Example score
    elif finding.severity == Severity.LOW:
        finding.score = 2.0   # Example score
    elif finding.severity == Severity.INFORMATIONAL:
        finding.score = 0.0   # Example score
    else:
        finding.score = 0.0 # Default score

    return finding

def aggregate_scores(findings: List[Finding]) -> float:
    """
    Aggregates the scores of multiple findings to calculate an overall score (e.g., security posture).

    Args:
        findings: A list of Finding objects.

    Returns:
        An aggregated score.
    """
    # This is a placeholder for aggregation logic.
    # You might sum scores, use the highest score, or apply a weighted average.
    if not findings:
        return 0.0
    return sum(f.score or 0.0 for f in findings) / len(findings) # Example: simple average
