import os
import time
import json
from typing import List, Optional, Dict, Any
import httpx
import asyncio
from backend.plugins.base_plugin import BasePlugin
from backend.config_types.models import ScanInput

# ZAP configuration
ZAP_API_KEY = os.environ.get("ZAP_API_KEY", "your_zap_api_key")
ZAP_API_URL = os.environ.get("ZAP_API_URL", "http://localhost:8080")


async def _zap_api_request(endpoint: str, params: Optional[Dict[str, Any]] = None, timeout: int = 30) -> Dict[str, Any]:
    """Helper to make async requests to the ZAP API."""
    headers = {'X-ZAP-API-Key': ZAP_API_KEY}
    url = f"{ZAP_API_URL}/JSON/{endpoint}"

    async with httpx.AsyncClient(timeout=timeout) as client:
        try:
            response = await client.get(url, headers=headers, params=params)
            response.raise_for_status()
            return response.json()
        except httpx.RequestError as e:
            raise Exception(f"Error interacting with ZAP API at {endpoint}: {e}")
        except httpx.TimeoutException:
            raise Exception(f"Timeout interacting with ZAP API at {endpoint}")


async def _check_zap_availability() -> bool:
    """Check if ZAP is running and accessible."""
    try:
        response = await _zap_api_request("core/view/version", timeout=5)
        return "version" in response
    except Exception:
        return False


async def _wait_for_zap_scan_completion(scan_id: str, scan_type: str = "spider", timeout: int = 300) -> bool:
    """Wait for a ZAP scan to complete."""
    start_time = time.time()

    while time.time() - start_time < timeout:
        try:
            if scan_type == "spider":
                status_data = await _zap_api_request("spider/view/status", {"scanId": scan_id})
            else:  # ascan
                status_data = await _zap_api_request("ascan/view/status", {"scanId": scan_id})

            progress = int(status_data.get('status', 0))
            if progress >= 100:
                return True

            await asyncio.sleep(2)  # Check every 2 seconds

        except Exception as e:
            print(f"Error checking {scan_type} status: {e}")
            await asyncio.sleep(5)

    return False


class OwaspZapPlugin(BasePlugin):
    """OWASP ZAP Plugin for web application security scanning with enhanced async capabilities."""

    async def _run_plugin(self, scan_input: ScanInput, config: Dict) -> List[Dict]:
        """Run the ZAP plugin scan."""
        try:
            # Check if ZAP is available
            if not await _check_zap_availability():
                return [self._create_error_finding(
                    "OWASP ZAP is not running or not accessible. Please start ZAP and ensure it's listening on the configured port."
                )]

            findings = await self._perform_zap_scan(scan_input, config)
            return findings
        except Exception as e:
            print(f"ZAP Plugin scan failed: {e}")
            return [self._create_error_finding(f"ZAP Plugin scan failed: {e}")]

    async def _perform_zap_scan(self, scan_input: ScanInput, config: Dict) -> List[Dict]:
        """Perform the actual ZAP scan with improved async handling."""
        target_url = scan_input.target

        try:
            # 1. Start the spider
            print(f"ZAP Spidering target: {target_url}")
            spider_result = await _zap_api_request("spider/action/scan/", {'url': target_url})
            spider_scan_id = spider_result.get('scan')

            if not spider_scan_id:
                return [self._create_error_finding("Failed to start ZAP spider scan")]

            # 2. Wait for spider to complete
            print(f"Monitoring ZAP Spider (ID: {spider_scan_id}) progress...")
            spider_completed = await _wait_for_zap_scan_completion(spider_scan_id, "spider", timeout=120)  # 2 min timeout

            if not spider_completed:
                print("Spider scan timed out, proceeding with active scan anyway")
            else:
                print("Spidering complete.")

            # 3. Start the active scan
            print(f"ZAP Active Scanning target: {target_url}")
            ascan_params = {
                'url': target_url,
                'recurse': 'True',
                'inScopeOnly': 'false'  # Scan everything found
            }

            # Add custom scan policy if specified
            scan_policy = config.get('scan_policy')
            if scan_policy:
                ascan_params['scanPolicyName'] = scan_policy

            ascan_result = await _zap_api_request("ascan/action/scan/", ascan_params)
            ascan_scan_id = ascan_result.get('scan')

            if not ascan_scan_id:
                return [self._create_error_finding("Failed to start ZAP active scan")]

            # 4. Wait for active scan to complete
            print(f"Monitoring ZAP Active Scan (ID: {ascan_scan_id}) progress...")
            ascan_completed = await _wait_for_zap_scan_completion(ascan_scan_id, "ascan", timeout=600)  # 10 min timeout

            if not ascan_completed:
                print("Active scan timed out")
                return [self._create_error_finding("ZAP active scan timed out after 10 minutes")]
            else:
                print("Active Scanning complete.")

            # 5. Retrieve scan results (alerts)
            print("Retrieving ZAP alerts...")
            alerts_data = await _zap_api_request("core/view/alerts/")
            alerts = alerts_data.get('alerts', [])

            # 6. Normalize ZAP alerts into Finding objects
            findings: List[Dict] = []
            for alert in alerts:
                finding = self._convert_zap_alert_to_finding(alert)
                if finding:
                    findings.append(finding)

            print(f"Retrieved {len(findings)} findings from ZAP.")
            return findings

        except Exception as e:
            print(f"Error during ZAP scan: {e}")
            return [self._create_error_finding(f"ZAP scan error: {e}")]

    def _convert_zap_alert_to_finding(self, alert: Dict) -> Optional[Dict]:
        """Convert a ZAP alert to a standardized finding format."""
        try:
            severity = alert.get('risk', 'Informational').lower()

            # Map ZAP risk to our severity
            severity_mapping = {
                'high': 'High',
                'medium': 'Medium',
                'low': 'Low',
                'informational': 'Info'
            }
            mapped_severity = severity_mapping.get(severity, 'Info')

            # Calculate CVSS based on severity
            cvss_mapping = {
                'High': 7.5,
                'Medium': 5.0,
                'Low': 2.5,
                'Info': 0.0
            }
            cvss = cvss_mapping.get(mapped_severity, 0.0)

            # Map confidence
            confidence_mapping = {
                'high': 90,
                'medium': 75,
                'low': 50,
                'false positive': 25
            }
            confidence = confidence_mapping.get(alert.get('confidence', 'medium').lower(), 75)

            # Build evidence
            evidence = {
                'url': alert.get('url', ''),
                'param': alert.get('param', ''),
                'attack': alert.get('attack', ''),
                'evidence': alert.get('evidence', ''),
                'other': alert.get('other', ''),
                'instances': alert.get('instances', [])
            }

            finding = {
                "type": alert.get('alert', 'ZAP Finding'),
                "severity": mapped_severity,
                "title": alert.get('name', 'ZAP Alert'),
                "description": alert.get('description', ''),
                "location": alert.get('url', ''),
                "cwe": alert.get('cweid', 'N/A'),
                "cve": "N/A",  # ZAP doesn't always provide CVE
                "remediation": alert.get('solution', 'Review and fix the identified issue'),
                "confidence": confidence,
                "cvss": cvss,
                "evidence": json.dumps(evidence, indent=2),
                "category": "OWASP_ZAP",
                "references": alert.get('reference', '').split('\n') if alert.get('reference') else []
            }

            return finding

        except Exception as e:
            print(f"Error converting ZAP alert to finding: {e}")
            return None

    def _create_error_finding(self, description: str) -> Dict:
        """Create an error finding."""
        return {
            "type": "error",
            "severity": "INFO",
            "title": "ZAP Plugin Error",
            "description": description,
            "location": "Plugin",
            "cwe": "N/A",
            "cve": "N/A",
            "remediation": "Check ZAP installation and configuration",
            "confidence": 0,
            "cvss": 0.0,
            "evidence": json.dumps({"error": description}),
            "category": "OWASP_ZAP"
        }
