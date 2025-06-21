from datetime import datetime
from typing import List, Dict, Any
import httpx
import json
from backend.utils.circuit_breaker import circuit_breaker
from backend.utils.logging_config import get_context_logger
from backend.scanners.base_scanner import BaseScanner
from backend.types.models import ScanInput, Severity, OwaspCategory

logger = get_context_logger(__name__)

class ApiSecurityScanner(BaseScanner):
    """
    A scanner module for detecting API security vulnerabilities.
    """

    metadata = {
        "name": "API Security",
        "description": "Detects API security vulnerabilities including improper API versioning, missing rate limiting, and insecure API endpoints.",
        "owasp_category": "A01:2021 - Broken Access Control",
        "author": "Project Nightingale Team",
        "version": "1.0"
    }

    @circuit_breaker(failure_threshold=3, recovery_timeout=30.0, name="api_security_scanner")
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
            results = await self._perform_scan(scan_input.target, scan_input.options)
            
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
        Perform the actual API security vulnerability scan.
        
        Args:
            target: Target URL to scan
            options: Scan options including timeout and test endpoints
            
        Returns:
            List of findings containing API security vulnerabilities
        """
        findings = []
        timeout = options.get('timeout', 10)
        
        # Common API endpoints to test
        api_endpoints = options.get('api_endpoints', [
            '/api',
            '/api/v1',
            '/api/v2',
            '/api/v3',
            '/api/docs',
            '/api/swagger',
            '/api/openapi',
            '/api/health',
            '/api/status',
            '/api/metrics',
            '/api/version',
            '/api/info',
            '/api/users',
            '/api/auth',
            '/api/token',
            '/api/oauth',
            '/api/login',
            '/api/register',
            '/api/profile',
            '/api/settings'
        ])
        
        # Common HTTP methods to test
        http_methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']
        
        # Common API version headers
        version_headers = [
            'Accept-Version',
            'API-Version',
            'X-API-Version',
            'Version'
        ]
        
        # Common API version values
        version_values = ['1', '2', '3', 'latest', 'stable', 'beta', 'alpha']
        
        async with httpx.AsyncClient(timeout=timeout) as client:
            try:
                # Test each API endpoint
                for endpoint in api_endpoints:
                    url = f"{target.rstrip('/')}/{endpoint.lstrip('/')}"
                    
                    try:
                        # First, check if endpoint exists
                        response = await client.get(url)
                        
                        if response.status_code != 404:
                            # Test each HTTP method
                            for method in http_methods:
                                try:
                                    # Test without version header
                                    if method == 'GET':
                                        method_response = await client.get(url)
                                    elif method == 'POST':
                                        method_response = await client.post(url)
                                    elif method == 'PUT':
                                        method_response = await client.put(url)
                                    elif method == 'DELETE':
                                        method_response = await client.delete(url)
                                    elif method == 'PATCH':
                                        method_response = await client.patch(url)
                                    elif method == 'OPTIONS':
                                        method_response = await client.options(url)
                                    elif method == 'HEAD':
                                        method_response = await client.head(url)
                                    else:
                                        continue
                                    
                                    # Check for missing version header
                                    if method_response.status_code == 200:
                                        findings.append({
                                            "type": "api_security",
                                            "severity": Severity.MEDIUM,
                                            "title": "Missing API Version Header",
                                            "description": f"API endpoint is accessible without version header using {method} method.",
                                            "evidence": {
                                                "url": url,
                                                "method": method,
                                                "status_code": method_response.status_code,
                                                "response_length": len(method_response.text)
                                            },
                                            "owasp_category": OwaspCategory.BROKEN_ACCESS_CONTROL,
                                            "recommendation": "Implement proper API versioning using version headers. This helps maintain backward compatibility and allows for graceful deprecation of old versions."
                                        })
                                    
                                    # Test with different version headers
                                    for header in version_headers:
                                        for version in version_values:
                                            try:
                                                # Add version header
                                                headers = {header: version}
                                                
                                                if method == 'GET':
                                                    version_response = await client.get(url, headers=headers)
                                                elif method == 'POST':
                                                    version_response = await client.post(url, headers=headers)
                                                elif method == 'PUT':
                                                    version_response = await client.put(url, headers=headers)
                                                elif method == 'DELETE':
                                                    version_response = await client.delete(url, headers=headers)
                                                elif method == 'PATCH':
                                                    version_response = await client.patch(url, headers=headers)
                                                elif method == 'OPTIONS':
                                                    version_response = await client.options(url, headers=headers)
                                                elif method == 'HEAD':
                                                    version_response = await client.head(url, headers=headers)
                                                else:
                                                    continue
                                                
                                                # Check for version header handling
                                                if version_response.status_code == 200:
                                                    # Check if version is in response
                                                    try:
                                                        response_json = version_response.json()
                                                        if isinstance(response_json, dict) and 'version' in response_json:
                                                            if response_json['version'] != version:
                                                                findings.append({
                                                                    "type": "api_security",
                                                                    "severity": Severity.MEDIUM,
                                                                    "title": "Inconsistent API Versioning",
                                                                    "description": f"API endpoint returns different version than requested. Requested: {version}, Received: {response_json['version']}",
                                                                    "evidence": {
                                                                        "url": url,
                                                                        "method": method,
                                                                        "header": header,
                                                                        "requested_version": version,
                                                                        "received_version": response_json['version'],
                                                                        "status_code": version_response.status_code
                                                                    },
                                                                    "owasp_category": OwaspCategory.BROKEN_ACCESS_CONTROL,
                                                                    "recommendation": "Ensure consistent API versioning. The version returned in the response should match the version requested in the header."
                                                                })
                                                    except json.JSONDecodeError:
                                                        pass
                                                
                                            except Exception as e:
                                                logger.warning(
                                                    f"Error testing version {version} with header {header} for {url}",
                                                    extra={
                                                        "url": url,
                                                        "method": method,
                                                        "header": header,
                                                        "version": version,
                                                        "error": str(e)
                                                    }
                                                )
                                                continue
                                    
                                    # Test rate limiting
                                    try:
                                        # Make multiple requests in quick succession
                                        responses = []
                                        for _ in range(10):
                                            if method == 'GET':
                                                response = await client.get(url)
                                            elif method == 'POST':
                                                response = await client.post(url)
                                            elif method == 'PUT':
                                                response = await client.put(url)
                                            elif method == 'DELETE':
                                                response = await client.delete(url)
                                            elif method == 'PATCH':
                                                response = await client.patch(url)
                                            elif method == 'OPTIONS':
                                                response = await client.options(url)
                                            elif method == 'HEAD':
                                                response = await client.head(url)
                                            else:
                                                continue
                                            responses.append(response)
                                        
                                        # Check if rate limiting is implemented
                                        rate_limited = any(
                                            response.status_code == 429 or
                                            'Retry-After' in response.headers or
                                            'X-RateLimit-Remaining' in response.headers
                                            for response in responses
                                        )
                                        
                                        if not rate_limited:
                                            findings.append({
                                                "type": "api_security",
                                                "severity": Severity.HIGH,
                                                "title": "Missing Rate Limiting",
                                                "description": f"API endpoint does not implement rate limiting for {method} method.",
                                                "evidence": {
                                                    "url": url,
                                                    "method": method,
                                                    "status_codes": [r.status_code for r in responses],
                                                    "headers": [dict(r.headers) for r in responses]
                                                },
                                                "owasp_category": OwaspCategory.BROKEN_ACCESS_CONTROL,
                                                "recommendation": "Implement rate limiting to prevent abuse and ensure fair usage of the API. Consider using standard headers like Retry-After and X-RateLimit-*."
                                            })
                                        
                                    except Exception as e:
                                        logger.warning(
                                            f"Error testing rate limiting for {url}",
                                            extra={
                                                "url": url,
                                                "method": method,
                                                "error": str(e)
                                            }
                                        )
                                    
                                except Exception as e:
                                    logger.warning(
                                        f"Error testing method {method} for {url}",
                                        extra={
                                            "url": url,
                                            "method": method,
                                            "error": str(e)
                                        }
                                    )
                                    continue
                            
                    except Exception as e:
                        logger.warning(
                            f"Error checking endpoint {url}",
                            extra={
                                "url": url,
                                "error": str(e)
                            }
                        )
                        continue
                
            except Exception as e:
                logger.warning(
                    f"Error scanning target {target}",
                    extra={
                        "target": target,
                        "error": str(e)
                    }
                )
                
        return findings 