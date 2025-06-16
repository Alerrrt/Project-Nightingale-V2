import os
import time
from typing import List, Optional, Dict, Any
import httpx # Using httpx for asynchronous requests
from pydantic import BaseModel, Field
import requests
import asyncio
from backend.types.models import Finding, ScanInput, Severity, OwaspCategory, HttpUrl

# Placeholder for ZAP API key - should be loaded from a secure source
ZAP_API_KEY = os.environ.get("ZAP_API_KEY", "your_zap_api_key")
ZAP_API_URL = os.environ.get("ZAP_API_URL", "http://localhost:8080")


class ZapScanStatus(BaseModel):
    status: str
    progress: str


class ZapAlert(BaseModel):
    sourceid: str
    pluginid: str
    alert: str
    name: str
    risk: str
    confidence: str
    url: str
    other: str
    param: str
    attack: str
    evidence: str
    description: str
    cweid: str
    wascid: str
    solution: str
    references: str
    instances: List[Dict[str, Any]]


async def _zap_api_request(endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Helper to make requests to the ZAP API."""
    headers = {'X-ZAP-API-Key': ZAP_API_KEY}
    url = f"{ZAP_API_URL}/JSON/{endpoint}"
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, headers=headers, params=params)
            response.raise_for_status()
            return response.json()
        except httpx.RequestError as e:
            print(f"Error interacting with ZAP API at {endpoint}: {e}")
            raise


async def start_zap() -> bool:
    """Starts the OWASP ZAP process (placeholder)."""
    # In a real scenario, this would involve running ZAP as a subprocess
    # or ensuring a running instance is available.
    print("Starting ZAP (placeholder)...")
    # Simulate startup time
    await asyncio.sleep(5)
    print("ZAP started (placeholder).")
    return True


async def stop_zap() -> bool:
    """Stops the OWASP ZAP process (placeholder)."""
    # In a real scenario, this would involve shutting down the ZAP subprocess.
    print("Stopping ZAP (placeholder)...")
    # Simulate shutdown time
    await asyncio.sleep(2)
    print("ZAP stopped (placeholder).")
    return True


async def zap_spider_and_scan(scan_input: ScanInput) -> List[Finding]:
    """Initiates a spider and active scan in ZAP and retrieves results."""
    target_url = scan_input.target

    # 1. Start the spider asynchronously
    print(f"ZAP Spidering target: {target_url}")
    spider_result = await _zap_api_request("spider/action/scan/", params={'url': target_url})
    spider_scan_id = spider_result.get('scan')

    # 2. Monitor spider progress asynchronously
    print(f"Monitoring ZAP Spider (ID: {spider_scan_id}) progress...")
    while True: # This loop will need to be carefully managed in a real async application
        spider_status_data = await _zap_api_request("spider/view/status/", params={'scanId': spider_scan_id})
        spider_progress = int(spider_status_data.get('status'))
        print(f"Spider Progress: {spider_progress}%")
        if spider_progress >= 100:
            break
        await asyncio.sleep(2)  # Wait for a few seconds before checking again

    print("Spidering complete.")

    # 3. Start the active scan asynchronously
    print(f"ZAP Active Scanning target: {target_url}")
    ascan_result = await _zap_api_request("ascan/action/scan/", params={'url': target_url, 'recurse': 'True'})
    ascan_scan_id = ascan_result.get('scan')

    # 4. Monitor active scan progress asynchronously
    print(f"Monitoring ZAP Active Scan (ID: {ascan_scan_id}) progress...")
    while True: # This loop will also need careful async management
        ascan_status_data = await _zap_api_request("ascan/view/status/", params={'scanId': ascan_scan_id})
        ascan_progress = int(ascan_status_data.get('status'))
        print(f"Active Scan Progress: {ascan_progress}%")
        if ascan_progress >= 100:
            break
        await asyncio.sleep(5)  # Wait for a few seconds before checking again

    print("Active Scanning complete.")

    # 5. Retrieve scan results (alerts) asynchronously
    print("Retrieving ZAP alerts...")
    alerts_data = await _zap_api_request("core/view/alerts/")
    zap_alerts: List[ZapAlert] = [ZapAlert(**alert) for alert in alerts_data.get('alerts', [])]

    # 6. Normalize ZAP alerts into Finding objects
    findings: List[Finding] = []
    for alert in zap_alerts:
        severity = alert.risk.lower()  # ZAP uses High, Medium, Low, Informational
        # Map ZAP risk to our severity (you might need a more detailed mapping)
        if severity == 'high':
            mapped_severity = Severity.HIGH
        elif severity == 'medium':
            mapped_severity = Severity.MEDIUM
        elif severity == 'low':
            mapped_severity = Severity.LOW
        elif severity == 'informational':
            mapped_severity = Severity.INFO
        else:
            mapped_severity = Severity.INFO # Default to Info for unknown

        proof_data = {
            "url": alert.url,
            "param": alert.param,
            "attack": alert.attack,
            "evidence": alert.evidence,
            "other": alert.other,
            "instances": alert.instances
        }

        finding = Finding(
            vulnerability_type=alert.alert,
            severity=mapped_severity,
            description=alert.description,
            technical_details=f"Plugin ID: {alert.pluginid}, CWE ID: {alert.cweid}, WASC ID: {alert.wascid}",
            remediation=alert.solution,
            owasp_category=OwaspCategory.UNKNOWN, # Use UNKNOWN for now or implement proper mapping
            proof=proof_data,
            affected_url=HttpUrl(alert.url) # Convert to HttpUrl
        )
        findings.append(finding)

    print(f"Retrieved {len(findings)} findings from ZAP.")
    return findings