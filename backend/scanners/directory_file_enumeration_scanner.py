import asyncio
import uuid
from typing import List, Optional, Dict, Any
import httpx
from datetime import datetime
from backend.utils.circuit_breaker import circuit_breaker
from backend.utils.logging_config import get_context_logger

from backend.scanners.base_scanner import BaseScanner
from backend.types.models import ScanInput, Finding, Severity, OwaspCategory

logger = get_context_logger(__name__)

class DirectoryFileEnumerationScanner(BaseScanner):
    """
    A scanner module for brute-forcing common paths to uncover hidden or forgotten resources.
    """

    metadata = {
        "name": "Directory and File Enumeration",
        "description": "Detects exposed directories and files through enumeration.",
        "owasp_category": "A05:2021 - Security Misconfiguration",
        "author": "Project Nightingale Team",
        "version": "1.0"
    }

    @circuit_breaker(failure_threshold=3, recovery_timeout=30.0, name="directory_file_enumeration_scanner")
    async def scan(self, scan_input: ScanInput) -> List[Dict]:
        """
        Perform a security scan with circuit breaker protection.
        
        Args:
            scan_input: The input for the scan, including target and options.
            
        Returns:
            List of scan results
        """
        start_time = datetime.now()
        scan_id = f"{self.__class__.__name__}_{start_time.strftime('%Y%m%d_%H%M%S')}"
        
        try:
            # Log scan start
            logger.info(
                "Scan started",
                extra={
                    "scanner": self.__class__.__name__,
                    "scan_id": scan_id,
                    "target": scan_input.target,
                    "options": scan_input.options
                }
            )
            
            # Perform scan
            options = scan_input.options if scan_input.options is not None else {}
            results = await self._perform_scan(scan_input.target, options)
            
            # Update metrics
            self._update_metrics(True, start_time)
            
            # Log scan completion
            logger.info(
                "Scan completed",
                extra={
                    "scanner": self.__class__.__name__,
                    "scan_id": scan_id,
                    "target": scan_input.target,
                    "result_count": len(results)
                }
            )
            
            return results
            
        except Exception as e:
            # Update metrics
            self._update_metrics(False, start_time)
            
            # Log error
            logger.error(
                "Scan failed",
                extra={
                    "scanner": self.__class__.__name__,
                    "scan_id": scan_id,
                    "target": scan_input.target,
                    "error": str(e)
                },
                exc_info=True
            )
            raise

    async def _perform_scan(self, target: str, options: Dict) -> List[Dict]:
        """
        Perform the actual directory and file enumeration scan.
        
        Args:
            target: Target URL to scan
            options: Scan options including wordlist and timeout
            
        Returns:
            List of findings containing discovered paths
        """
        findings = []
        common_paths = options.get('wordlist', [
            '/admin', '/backup', '/config', '/db', '/debug',
            '/dev', '/docs', '/files', '/images', '/includes',
            '/install', '/logs', '/media', '/phpinfo.php',
            '/robots.txt', '/server-status', '/sql', '/temp',
            '/test', '/tmp', '/upload', '/uploads', '/vendor'
        ])
        
        timeout = options.get('timeout', 10)
        async with httpx.AsyncClient(timeout=timeout) as client:
            
            async def check_path(path: str) -> Optional[Dict]:
                try:
                    url = f"{target.rstrip('/')}/{path.lstrip('/')}"
                    response = await client.get(url)
                    
                    if response.status_code < 400:  # Found something
                        return {
                            "type": "vulnerability",
                            "severity": Severity.MEDIUM.value,
                            "cwe": "CWE-538", # File and Directory Information Exposure
                            "title": f"Exposed Path Found: {path}",
                            "description": f"An accessible path was discovered at {url}, which returned a status code of {response.status_code}. This could expose sensitive files, directory listings, or functionality.",
                            "location": url,
                            "remediation": "Ensure that sensitive files and directories are not publicly accessible. Configure your web server to show a 404 Not Found error instead of a 403 Forbidden error for non-existent resources to avoid path enumeration. Restrict access to authorized users where necessary.",
                            "confidence": 100,
                            "impact": "Information disclosure, potential for further attacks.",
                            "cvss": 5.3,
                            "category": OwaspCategory.SECURITY_MISCONFIGURATION.value,
                        }
                except httpx.RequestError as e:
                    logger.warning(
                        f"Error checking path {path}: {type(e).__name__}",
                        extra={"target": target, "path": path}
                    )
                return None

            tasks = [check_path(path) for path in common_paths]
            results = await asyncio.gather(*tasks)
            
            findings = [res for res in results if res is not None]
                    
        return findings 