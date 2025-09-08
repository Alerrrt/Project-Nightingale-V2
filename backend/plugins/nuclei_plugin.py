import logging
import subprocess
import json
import asyncio
import os
import tempfile
from typing import List, Dict, Optional
from backend.plugins.base_plugin import BasePlugin
from backend.config_types.models import ScanInput

logger = logging.getLogger(__name__)

class NucleiPlugin(BasePlugin):
    """Nuclei vulnerability scanner plugin with enhanced capabilities."""

    def __init__(self):
        super().__init__()
        self.nuclei_path = self._find_nuclei_binary()
        self.templates_path = self._get_templates_path()

    def _find_nuclei_binary(self) -> Optional[str]:
        """Find the nuclei binary in common locations."""
        common_paths = [
            "/usr/local/bin/nuclei",
            "/usr/bin/nuclei",
            "/opt/homebrew/bin/nuclei",  # macOS with Homebrew
            "C:\\Program Files\\nuclei\\nuclei.exe",  # Windows
            "C:\\nuclei\\nuclei.exe",
            "./nuclei",  # Current directory
            "nuclei.exe"  # Windows current directory
        ]

        # Check PATH first
        try:
            result = subprocess.run(["which", "nuclei"], capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip()
        except (subprocess.SubprocessError, FileNotFoundError):
            pass

        # Check common paths
        for path in common_paths:
            if os.path.exists(path) and os.access(path, os.X_OK):
                return path

        return None

    def _get_templates_path(self) -> Optional[str]:
        """Get the path to nuclei templates."""
        if not self.nuclei_path:
            return None

        # Try to find templates in common locations
        common_template_paths = [
            "/usr/share/nuclei-templates",
            "/opt/homebrew/share/nuclei-templates",
            "C:\\Program Files\\nuclei\\templates",
            "C:\\nuclei\\templates",
            "./nuclei-templates",
            os.path.join(os.path.dirname(self.nuclei_path), "..", "share", "nuclei-templates")
        ]

        for path in common_template_paths:
            if os.path.exists(path):
                return path

        return None

    async def _run_plugin(self, scan_input: ScanInput, config: Dict) -> List[Dict]:
        """Run the Nuclei plugin scan."""
        try:
            if not self.nuclei_path:
                logger.warning("Nuclei binary not found. Install nuclei to enable this scanner.")
                return [self._create_error_finding(
                    "Nuclei binary not found. Please install nuclei from https://github.com/projectdiscovery/nuclei"
                )]

            return await self._perform_scan(scan_input.target, config)
        except Exception as e:
            logger.error(f"Nuclei Plugin scan failed: {e}", exc_info=True)
            return [self._create_error_finding(f"Nuclei Plugin scan failed: {e}")]

    async def _perform_scan(self, target: str, options: Dict) -> List[Dict]:
        """Perform the actual Nuclei scan with enhanced capabilities."""
        findings = []

        try:
            # Create temporary file for results
            with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as temp_file:
                temp_output_file = temp_file.name

            # Build nuclei command with enhanced options
            cmd = [
                self.nuclei_path,
                "-u", target,
                "-json",
                "-o", temp_output_file,
                "-silent",
                "-no-interactsh",  # Disable interactsh for faster scanning
                "-rate-limit", "150",  # Reasonable rate limit
                "-bulk-size", "25",  # Process templates in batches
                "-timeout", "10",  # 10 second timeout per template
            ]

            # Add severity filtering if specified
            severity_filter = options.get("severity", [])
            if severity_filter:
                cmd.extend(["-severity", ",".join(severity_filter)])

            # Add template filters if specified
            template_tags = options.get("tags", [])
            if template_tags:
                cmd.extend(["-tags", ",".join(template_tags)])

            # Add custom templates path if available
            if self.templates_path:
                cmd.extend(["-t", self.templates_path])

            # Add additional nuclei options for better scanning
            cmd.extend([
                "-stats",  # Show statistics
                "-no-meta",  # Don't show metadata
                "-no-color",  # Disable colors for JSON output
            ])

            logger.info(f"Running nuclei scan on {target} with command: {' '.join(cmd)}")

            # Run nuclei with timeout
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            try:
                # Wait for completion with reasonable timeout
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=300  # 5 minutes timeout
                )

                return_code = process.returncode
                logger.info(f"Nuclei scan completed with return code: {return_code}")

                if return_code not in [0, 1]:  # 0 = success, 1 = findings found
                    error_msg = stderr.decode('utf-8', errors='ignore') if stderr else "Unknown error"
                    logger.error(f"Nuclei scan failed: {error_msg}")
                    return [self._create_error_finding(f"Nuclei scan failed: {error_msg}")]

                # Parse results
                findings = await self._parse_nuclei_results(temp_output_file)

            except asyncio.TimeoutError:
                logger.warning(f"Nuclei scan timed out for {target}")
                process.kill()
                return [self._create_error_finding("Nuclei scan timed out after 5 minutes")]

            finally:
                # Clean up temp file
                try:
                    os.unlink(temp_output_file)
                except OSError:
                    pass

        except Exception as e:
            logger.error(f"Failed to run nuclei scan on {target}: {e}")
            return [self._create_error_finding(f"Could not run nuclei scan: {e}")]

        logger.info(f"Nuclei scan completed for {target}, found {len(findings)} vulnerabilities")
        return findings

    async def _parse_nuclei_results(self, output_file: str) -> List[Dict]:
        """Parse nuclei JSON output into standardized findings."""
        findings = []

        try:
            if not os.path.exists(output_file):
                logger.warning(f"Nuclei output file not found: {output_file}")
                return findings

            with open(output_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        result = json.loads(line)
                        finding = self._convert_nuclei_result_to_finding(result)
                        if finding:
                            findings.append(finding)
                    except json.JSONDecodeError as e:
                        logger.warning(f"Failed to parse nuclei result line: {e}")
                        continue

        except Exception as e:
            logger.error(f"Error parsing nuclei results: {e}")

        return findings

    def _convert_nuclei_result_to_finding(self, nuclei_result: Dict) -> Optional[Dict]:
        """Convert a nuclei result to a standardized finding format."""
        try:
            # Extract key information from nuclei result
            template_info = nuclei_result.get("info", {})
            matched_at = nuclei_result.get("matched-at", "")
            severity = nuclei_result.get("severity", "info").upper()

            # Map nuclei severity to our severity scale
            severity_mapping = {
                "CRITICAL": "Critical",
                "HIGH": "High",
                "MEDIUM": "Medium",
                "LOW": "Low",
                "INFO": "Info",
                "UNKNOWN": "Info"
            }
            mapped_severity = severity_mapping.get(severity, "Info")

            # Extract CWE and CVE if available
            cwe = "N/A"
            cve = "N/A"
            tags = template_info.get("tags", [])
            for tag in tags:
                if tag.startswith("cwe-"):
                    cwe = tag.upper()
                elif tag.startswith("CVE-"):
                    cve = tag.upper()

            # Build evidence from nuclei result
            evidence = {
                "url": matched_at,
                "template": nuclei_result.get("template", ""),
                "type": nuclei_result.get("type", ""),
                "host": nuclei_result.get("host", ""),
                "matched-at": matched_at,
                "extracted-results": nuclei_result.get("extracted-results", []),
                "meta": nuclei_result.get("meta", {})
            }

            # Calculate confidence based on nuclei's confidence score
            confidence = nuclei_result.get("confidence", 75)
            if isinstance(confidence, str):
                confidence_mapping = {
                    "high": 90,
                    "medium": 75,
                    "low": 50
                }
                confidence = confidence_mapping.get(confidence.lower(), 75)

            # Calculate CVSS score based on severity
            cvss_mapping = {
                "Critical": 9.5,
                "High": 7.5,
                "Medium": 5.0,
                "Low": 2.5,
                "Info": 0.0
            }
            cvss = cvss_mapping.get(mapped_severity, 0.0)

            finding = {
                "type": template_info.get("name", "Nuclei Finding"),
                "severity": mapped_severity,
                "title": template_info.get("name", "Nuclei Vulnerability"),
                "description": template_info.get("description", "Vulnerability detected by Nuclei scanner"),
                "location": matched_at,
                "cwe": cwe,
                "cve": cve,
                "remediation": template_info.get("remediation", "Follow security best practices and review the vulnerability details"),
                "confidence": confidence,
                "cvss": cvss,
                "evidence": json.dumps(evidence, indent=2),
                "category": "NUCLEI",
                "references": template_info.get("reference", []),
                "tags": tags
            }

            return finding

        except Exception as e:
            logger.error(f"Error converting nuclei result to finding: {e}")
            return None

    def _create_error_finding(self, description: str) -> Dict:
        """Create an error finding."""
        return {
            "type": "error",
            "severity": "INFO",
            "title": "Nuclei Plugin Error",
            "description": description,
            "location": "Plugin",
            "cwe": "N/A",
            "cve": "N/A",
            "remediation": "Check nuclei installation and configuration",
            "confidence": 0,
            "cvss": 0.0,
            "evidence": json.dumps({"error": description}),
            "category": "NUCLEI"
        }
