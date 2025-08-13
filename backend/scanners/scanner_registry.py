import asyncio
import logging
import importlib
import pkgutil
import inspect
import os
from typing import Dict, Type, List, Optional, Set
from functools import lru_cache
from dataclasses import dataclass, field
from threading import Lock
from backend.scanners.base_scanner import BaseScanner
from backend.types.scanner_config import ScannerRegistryConfig, ScannerConfig, ScannerIntensity
from backend.utils.logging_config import get_context_logger
from backend.utils.resource_monitor import ResourceMonitor
from backend.config import AppConfig

logger = get_context_logger(__name__)

@dataclass
class ScannerRegistryConfig:
    """Configuration for scanner registry."""
    default_timeout: int = 30
    default_max_retries: int = 3
    batch_size: int = 5
    max_concurrent_scans: int = 10
    resource_limits: Dict[str, float] = field(default_factory=dict)

class ScannerRegistry:
    """
    A registry for managing scanner modules.
    """
    _instance: Optional['ScannerRegistry'] = None
    _lock = Lock()
    _scanners: Dict[str, Type[BaseScanner]] = {}
    _scanner_metadata_cache: Dict[str, dict] = {}
    _enabled_scanners_cache: Optional[List[str]] = None
    _resource_monitor: Optional[ResourceMonitor] = None
    _initialized: bool = False

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, config: Optional[AppConfig] = None):
        if not self._initialized:
            with self._lock:
                if not self._initialized:
                    self._config = config or AppConfig.load_from_env()
                    self._resource_monitor = ResourceMonitor(self._config.resource_limits)
                    self._scanner_configs: Dict[str, ScannerConfig] = {}
                    self._initialized = True

    @classmethod
    def get_instance(cls, config: Optional[AppConfig] = None) -> 'ScannerRegistry':
        """Get or create the singleton instance of ScannerRegistry."""
        if cls._instance is None:
            cls._instance = cls(config)
        elif config is not None:
            cls._instance.configure(config)
        return cls._instance

    def configure(self, config: AppConfig) -> None:
        """Configure the scanner registry with new settings."""
        self._config = config
        if self._resource_monitor:
            self._resource_monitor = ResourceMonitor(config.resource_limits)
        self._scanner_configs.clear()
        self._scanner_metadata_cache.clear()
        self._enabled_scanners_cache = None

    def get_config(self) -> AppConfig:
        """Get the current configuration."""
        return self._config

    @lru_cache(maxsize=100)
    def get_scanner_config(self, scanner_name: str) -> ScannerConfig:
        """Get configuration for a specific scanner."""
        if scanner_name not in self._scanner_configs:
            self._scanner_configs[scanner_name] = ScannerConfig(
                timeout=self._config.scanner_config.default_timeout,
                max_retries=self._config.scanner_config.default_max_retries,
                options={}
            )
        return self._scanner_configs[scanner_name]

    def register(self, scanner_name: str, scanner_class: Type[BaseScanner]) -> None:
        """
        Register a scanner module.

        Args:
            scanner_name: The name of the scanner.
            scanner_class: The scanner class to register.
        """
        if not issubclass(scanner_class, BaseScanner):
            raise TypeError(f"Scanner class must inherit from BaseScanner: {scanner_name}")
        # Skip abstract classes or scanners that didn't implement _perform_scan
        import inspect as _inspect
        try:
            if _inspect.isabstract(scanner_class):
                logger.warning(f"Skipping abstract scanner: {scanner_class.__name__}")
                return
            # Ensure _perform_scan overridden
            if getattr(scanner_class, '_perform_scan', None) is getattr(BaseScanner, '_perform_scan', None):
                logger.warning(f"Skipping scanner without _perform_scan implementation: {scanner_class.__name__}")
                return
        except Exception:
            pass
        
        if scanner_name in self._scanners:
            logger.warning(f"Overwriting existing scanner registration: {scanner_name}")
        
        self._scanners[scanner_name] = scanner_class
        self._enabled_scanners_cache = None  # Invalidate cache
        logger.info(
            "Scanner registered",
            extra={
                "scanner_name": scanner_name,
                "class": scanner_class.__name__
            }
        )

    def get_scanner(self, scanner_name: str):
        """Return the scanner class by name or None if missing."""
        scanner = self._scanners.get(scanner_name)
        if scanner is None:
            logger.error(f"Scanner '{scanner_name}' not found")
        return scanner
    def _create_error_finding(self, description: str) -> dict:
        # Deprecated: Not used anymore to avoid returning non-class from get_scanner
        return { "type": "error", "severity": "INFO", "title": "Scanner Registry Error", "description": description, "location": "Registry", "cwe": "N/A", "remediation": "N/A", "confidence": 0, "cvss": 0 }

    def get_all_scanners(self) -> Dict[str, Type[BaseScanner]]:
        """
        Get all registered scanners.
        """
        return self._scanners.copy()

    @lru_cache(maxsize=1)
    def get_all_scanner_metadata(self) -> Dict[str, dict]:
        """
        Get metadata for all registered scanners with caching.
        """
        metadata = {}
        for name, scanner_class in self._scanners.items():
            md = getattr(scanner_class, 'metadata', {}) or {}
            # Normalize and ensure required fields for industrial-grade catalog
            normalized = {
                'name': md.get('name', scanner_class.__name__),
                'description': md.get('description', ''),
                'owasp_category': md.get('owasp_category', 'Unknown'),
                'author': md.get('author', ''),
                'version': md.get('version', '1.0.0'),
            }
            metadata[name] = normalized
        return metadata

    def get_enhanced_scanner_metadata(self) -> Dict[str, dict]:
        """
        Get enhanced metadata for all registered scanners with detailed OWASP and vulnerability information.
        """
        metadata = {}
        
        # Comprehensive scanner metadata mapping
        scanner_details = {
            'authentication_scanner': {
                'name': 'Authentication Scanner',
                'description': 'Tests for broken authentication mechanisms and session management vulnerabilities',
                'owasp_category': 'A07:2021 - Identification and Authentication Failures',
                'vulnerability_types': ['Weak Passwords', 'Session Fixation', 'Insecure Session Management', 'Credential Stuffing'],
                'scan_type': 'Authentication & Session',
                'intensity': 'Medium'
            },
            'broken_access_control_scanner': {
                'name': 'Access Control Scanner',
                'description': 'Detects broken access control vulnerabilities and authorization bypasses',
                'owasp_category': 'A01:2021 - Broken Access Control',
                'vulnerability_types': ['Horizontal Privilege Escalation', 'Vertical Privilege Escalation', 'IDOR', 'Missing Authorization'],
                'scan_type': 'Authorization',
                'intensity': 'High'
            },
            'sql_injection_scanner': {
                'name': 'SQL Injection Scanner',
                'description': 'Detects SQL injection vulnerabilities using various attack payloads',
                'owasp_category': 'A03:2021 - Injection',
                'vulnerability_types': ['SQL Injection', 'Blind SQL Injection', 'Time-based SQL Injection', 'Error-based SQL Injection'],
                'scan_type': 'Injection',
                'intensity': 'High'
            },
            'xss_scanner': {
                'name': 'Cross-Site Scripting Scanner',
                'description': 'Detects Cross-Site Scripting (XSS) vulnerabilities in web applications',
                'owasp_category': 'A03:2021 - Cross-Site Scripting (XSS)',
                'vulnerability_types': ['Reflected XSS', 'Stored XSS', 'DOM-based XSS', 'Blind XSS'],
                'scan_type': 'Client-Side',
                'intensity': 'High'
            },
            'server_side_request_forgery_scanner': {
                'name': 'SSRF Scanner',
                'description': 'Detects Server-Side Request Forgery vulnerabilities',
                'owasp_category': 'A10:2021 - Server-Side Request Forgery (SSRF)',
                'vulnerability_types': ['SSRF', 'Internal Network Access', 'Cloud Metadata Access', 'Service Enumeration'],
                'scan_type': 'Server-Side',
                'intensity': 'High'
            },
            'security_headers_analyzer': {
                'name': 'Security Headers Analyzer',
                'description': 'Analyzes security headers for misconfigurations and missing protections',
                'owasp_category': 'A05:2021 - Security Misconfiguration',
                'vulnerability_types': ['Missing Security Headers', 'Weak CSP', 'Insecure Headers', 'Clickjacking Vulnerabilities'],
                'scan_type': 'Configuration',
                'intensity': 'Low'
            },
            'cors_misconfiguration_scanner': {
                'name': 'CORS Misconfiguration Scanner',
                'description': 'Detects Cross-Origin Resource Sharing misconfigurations',
                'owasp_category': 'A05:2021 - Security Misconfiguration',
                'vulnerability_types': ['CORS Misconfiguration', 'Overly Permissive CORS', 'Missing CORS Headers'],
                'scan_type': 'Configuration',
                'intensity': 'Medium'
            },
            'csrf_scanner': {
                'name': 'CSRF Scanner',
                'description': 'Detects Cross-Site Request Forgery vulnerabilities',
                'owasp_category': 'A01:2021 - Broken Access Control',
                'vulnerability_types': ['CSRF', 'Missing CSRF Tokens', 'Weak CSRF Protection'],
                'scan_type': 'Client-Side',
                'intensity': 'Medium'
            },
            'csrf_token_checker': {
                'name': 'CSRF Token Checker',
                'description': 'Validates CSRF token implementation and strength',
                'owasp_category': 'A01:2021 - Broken Access Control',
                'vulnerability_types': ['Weak CSRF Tokens', 'Missing CSRF Protection', 'Predictable Tokens'],
                'scan_type': 'Authentication',
                'intensity': 'Low'
            },
            'directory_file_enumeration_scanner': {
                'name': 'Directory Enumeration Scanner',
                'description': 'Discovers sensitive files and directories through enumeration',
                'owasp_category': 'A05:2021 - Security Misconfiguration',
                'vulnerability_types': ['Information Disclosure', 'Sensitive File Exposure', 'Directory Listing'],
                'scan_type': 'Enumeration',
                'intensity': 'Medium'
            },
            'open_redirect_scanner': {
                'name': 'Open Redirect Scanner',
                'description': 'Detects open redirect vulnerabilities in web applications',
                'owasp_category': 'A01:2021 - Broken Access Control',
                'vulnerability_types': ['Open Redirect', 'Unvalidated Redirects', 'Forward Vulnerabilities'],
                'scan_type': 'Client-Side',
                'intensity': 'Medium'
            },
            'ssl_tls_configuration_audit_scanner': {
                'name': 'SSL/TLS Configuration Scanner',
                'description': 'Audits SSL/TLS configuration for security weaknesses',
                'owasp_category': 'A02:2021 - Cryptographic Failures',
                'vulnerability_types': ['Weak Ciphers', 'Outdated Protocols', 'Certificate Issues', 'TLS Misconfiguration'],
                'scan_type': 'Cryptography',
                'intensity': 'Medium'
            },
            'technology_fingerprint_scanner': {
                'name': 'Technology Fingerprint Scanner',
                'description': 'Identifies technologies and frameworks used by the target',
                'owasp_category': 'A06:2021 - Vulnerable and Outdated Components',
                'vulnerability_types': ['Technology Disclosure', 'Version Information', 'Framework Identification'],
                'scan_type': 'Reconnaissance',
                'intensity': 'Low'
            },
            'technology_vulnerabilities_scanner': {
                'name': 'Technology Vulnerabilities Scanner',
                'description': 'Scans for known vulnerabilities in identified technologies',
                'owasp_category': 'A06:2021 - Vulnerable and Outdated Components',
                'vulnerability_types': ['Known CVEs', 'Outdated Components', 'Vulnerable Libraries'],
                'scan_type': 'Vulnerability Assessment',
                'intensity': 'Medium'
            },
            'subdomain_dns_enumeration_scanner': {
                'name': 'Subdomain Enumeration Scanner',
                'description': 'Discovers subdomains and DNS-related vulnerabilities',
                'owasp_category': 'A05:2021 - Security Misconfiguration',
                'vulnerability_types': ['Subdomain Takeover', 'DNS Misconfiguration', 'Information Disclosure'],
                'scan_type': 'Enumeration',
                'intensity': 'Low'
            },
            'rate_limiting_bruteforce_scanner': {
                'name': 'Rate Limiting Scanner',
                'description': 'Tests for rate limiting and brute force protection weaknesses',
                'owasp_category': 'A07:2021 - Identification and Authentication Failures',
                'vulnerability_types': ['Brute Force Vulnerabilities', 'Missing Rate Limiting', 'Weak Rate Limiting'],
                'scan_type': 'Authentication',
                'intensity': 'Medium'
            }
        }
        
        for name, scanner_class in self._scanners.items():
            # Get base metadata from scanner class
            md = getattr(scanner_class, 'metadata', {}) or {}
            
            # Get detailed information from our mapping
            details = scanner_details.get(name, {})
            
            # Combine and normalize
            normalized = {
                'name': details.get('name', md.get('name', scanner_class.__name__)),
                'description': details.get('description', md.get('description', '')),
                'owasp_category': details.get('owasp_category', str(md.get('owasp_category', 'Unknown'))),
                'vulnerability_types': details.get('vulnerability_types', []),
                'scan_type': details.get('scan_type', 'General'),
                'intensity': details.get('intensity', 'Medium'),
                'author': md.get('author', 'Project Nightingale Team'),
                'version': md.get('version', '1.0.0'),
            }
            
            metadata[name] = normalized
            
        return metadata

    def get_enabled_scanners(self) -> List[str]:
        """
        Get a list of enabled scanner names.
        """
        if self._enabled_scanners_cache is not None:
            return self._enabled_scanners_cache

        enabled = []
        for scanner_name in self._scanners:
            config = self.get_scanner_config(scanner_name)
            if config.enabled:
                enabled.append(scanner_name)
        
        self._enabled_scanners_cache = enabled
        return enabled

    async def load_scanners(self):
        """Load all available scanners."""
        try:
            scanners_dir = os.path.dirname(os.path.abspath(__file__))
            logger.info(f"Loading scanners from directory: {scanners_dir}")
            loaded_count = 0
            
            for filename in os.listdir(scanners_dir):
                if filename.endswith('.py') and not filename.startswith('__'):
                    module_name = filename[:-3]  # Remove .py extension
                    logger.info(f"Processing scanner module: {module_name}")
                    try:
                        # Import module
                        module = importlib.import_module(f'backend.scanners.{module_name}')
                        logger.info(f"Successfully imported module: {module_name}")
                        
                        # Find scanner classes in the module
                        for name, obj in inspect.getmembers(module):
                            logger.info(f"Checking object: {name} (type: {type(obj)})")
                            if (inspect.isclass(obj) and 
                                issubclass(obj, BaseScanner) and 
                                obj != BaseScanner):
                                
                                logger.info(f"Found scanner class: {name}")
                                # Primary name from class: e.g., CorsMisconfigurationScanner -> corsmisconfiguration
                                scanner_name = name.lower().replace('scanner', '')
                                self.register(scanner_name, obj)
                                # Also register an alias using the module filename: e.g., cors_misconfiguration_scanner
                                try:
                                    if module_name not in self._scanners:
                                        self.register(module_name, obj)
                                except Exception:
                                    # Non-fatal if alias already exists
                                    pass
                                loaded_count += 1
                                logger.info(f"Registered scanner: {scanner_name} and {module_name}")
                                
                    except Exception as e:
                        logger.error(
                            f"Error loading scanner module: {module_name}",
                            extra={"error": str(e)},
                            exc_info=True
                        )
            
            logger.info(
                "Scanners loaded",
                extra={
                    "scanner_count": len(self._scanners),
                    "loaded_count": loaded_count
                }
            )

            from backend.config import settings
            # Prune to industry-standard allowlist to avoid duplicates/unwanted modules
            allowed: Set[str] = {
                # Core OWASP families and essentials (module filenames or aliases)
                "authentication_scanner",
                "broken_access_control_scanner",
                "sql_injection_scanner",
                "xss_scanner",
                "server_side_request_forgery_scanner",
                "security_headers_analyzer",
                "cors_misconfiguration_scanner",
                "csrf_scanner",
                "csrf_token_checker",
                "directory_file_enumeration_scanner",
                "open_redirect_scanner",
                "ssl_tls_configuration_audit_scanner",
                "technology_fingerprint_scanner",
                "technology_vulnerabilities_scanner",
                "subdomain_dns_enumeration_scanner",
                "rate_limiting_bruteforce_scanner",
            }
            # Keep any alias registered under class-name form if it maps to an allowed module
            to_keep: Dict[str, Type[BaseScanner]] = {}
            for key, cls in list(self._scanners.items()):
                if key in allowed:
                    to_keep[key] = cls
            # Preserve class-name alias if its module alias is kept
            for key, cls in list(self._scanners.items()):
                module_alias = getattr(cls, "__module__", "").split(".")[-1]
                if module_alias in allowed:
                    to_keep[key] = cls
            if getattr(settings, 'SCANNER_PRUNING_ENABLED', False):
                removed = set(self._scanners.keys()) - set(to_keep.keys())
                self._scanners = to_keep
                if removed:
                    logger.info("Pruned scanners", extra={"removed": sorted(list(removed)), "kept": sorted(list(self._scanners.keys()))})
            else:
                logger.info("Scanner pruning disabled; keeping all discovered scanners")
            
        except Exception as e:
            logger.error("Error loading scanners", exc_info=True)
            raise

    def discover_and_register_scanners(self) -> None:
        """
        Deprecated: Use load_scanners() instead.
        This method is kept for backward compatibility.
        """
        logger.warning("discover_and_register_scanners is deprecated, use load_scanners() instead")
        asyncio.create_task(self.load_scanners())

    def clear(self) -> None:
        """
        Clear all registered scanners and caches.
        """
        self._scanners.clear()
        self._scanner_metadata_cache.clear()
        self._enabled_scanners_cache = None
        self.get_scanner_config.cache_clear()
        self.get_all_scanner_metadata.cache_clear()
        logger.info("Scanner registry cleared")

    async def check_scanner_health(self, name: str) -> bool:
        """Check health of a scanner."""
        try:
            scanner = self.get_scanner(name)
            if not scanner:
                return False
                
            # Create instance
            instance = scanner()
            
            # Check health
            return await instance.check_health()
            
        except Exception as e:
            logger.error(
                f"Error checking scanner health: {name}",
                exc_info=True
            )
            return False

    async def get_scanner_metrics(self, name: str) -> Dict:
        """Get metrics for a scanner."""
        try:
            scanner = self.get_scanner(name)
            if not scanner:
                return {}
                
            # Create instance
            instance = scanner()
            
            # Get metrics
            return instance.get_metrics()
            
        except Exception as e:
            logger.error(
                f"Error getting scanner metrics: {name}",
                exc_info=True
            )
            return {}

    def get_scanners(self) -> List[str]:
        """Get list of available scanner names."""
        return list(self._scanners.keys()) 
