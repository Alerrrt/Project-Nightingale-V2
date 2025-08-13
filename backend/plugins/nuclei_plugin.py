import asyncio
import json
import shlex
import logging
import uuid
from typing import List, Dict, Any, Optional

from backend.types.models import ScanInput, Finding, Severity, OwaspCategory

logger = logging.getLogger(__name__)

class NucleiPlugin:
    """
    Handles integration with the Nuclei vulnerability scanner.
    """

    def __init__(self, nuclei_path: str = "nuclei"):
        """
        Initializes the Nuclei plugin with the path to the nuclei executable.

        Args:
            nuclei_path: The path to the nuclei executable.
        """
        self.nuclei_path = nuclei_path

    async def run_scan(self, scan_input: ScanInput, templates: Optional[List[str]] = None) -> List[Finding]: # type: ignore
        """
        Runs a Nuclei scan against the target URL using specified templates.
        Uses asynchronous subprocess execution for efficiency.

        Args:
            scan_input: The ScanInput object containing the target URL.
            templates: A list of Nuclei template paths or names to use.

        Returns:
            A list of Finding objects.
        """
        logger.info(f"Starting Nuclei scan for {scan_input.target}")
        findings: List[Finding] = []

        # Build the Nuclei command
        command = [self.nuclei_path, '-u', str(scan_input.target), '-json'] # Convert HttpUrl to string
        if templates:
            command.extend(['-t', ','.join(templates)])

        logger.debug(f"Nuclei command: {' '.join(shlex.quote(arg) for arg in command)}")

        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                logger.error(f"Nuclei scan failed for {scan_input.target}: {stderr.decode()}")
                return []

            # Parse Nuclei's JSON output line by line
            for line in stdout.decode().splitlines():
                try:
                    nuclei_finding = json.loads(line)
                    
                    # Map Nuclei severity to our Severity enum
                    severity_map = {
                        "critical": Severity.CRITICAL,
                        "high": Severity.HIGH,
                        "medium": Severity.MEDIUM,
                        "low": Severity.LOW,
                        "info": Severity.INFO,
                        "unknown": Severity.INFO
                    }
                    nuclei_severity = nuclei_finding.get("info", {}).get("severity", "unknown").lower()
                    mapped_severity = severity_map.get(nuclei_severity, Severity.INFO)

                    # Map Nuclei tags/info to OWASP categories
                    owasp_category = OwaspCategory.UNKNOWN
                    if "cve" in nuclei_finding.get("info", {}).get("tags", []):
                        owasp_category = OwaspCategory.A06_VULNERABLE_AND_OUTDATED_COMPONENTS
                    elif "sqli" in nuclei_finding.get("info", {}).get("tags", []):
                        owasp_category = OwaspCategory.A03_INJECTION
                    # Add more specific mappings as needed

                    finding = Finding(
                        id=str(uuid.uuid4()),
                        vulnerability_type=nuclei_finding.get("info", {}).get("name", "Nuclei Finding"),
                        severity=mapped_severity,
                        description=nuclei_finding.get("info", {}).get("description", "No description provided."),
                        technical_details=json.dumps(nuclei_finding, indent=2),
                        remediation=nuclei_finding.get("info", {}).get("remediation", "See Nuclei template information."),
                        owasp_category=owasp_category,
                        affected_url=nuclei_finding.get("matched-at", str(scan_input.target)),
                        proof=nuclei_finding.get("extracted-results", nuclei_finding.get("matched-at", "No proof provided.")),
                        title=nuclei_finding.get("info", {}).get("name"),
                        cwe_id=nuclei_finding.get("info", {}).get("cwe-id"),
                    )
                    findings.append(finding)
                except json.JSONDecodeError:
                    logger.warning(f"Could not decode Nuclei JSON output line: {line}")
                except Exception as e:
                    logger.error(f"Error processing Nuclei finding: {e}", exc_info=True)

            return findings
        except FileNotFoundError:
            logger.error(f"Error: Nuclei executable not found at {self.nuclei_path}. Is Nuclei installed and in your PATH or specified correctly?")
            return []
        except Exception as e:
            logger.error(f"Error running Nuclei scan: {e}", exc_info=True)
            return []

        Returns
