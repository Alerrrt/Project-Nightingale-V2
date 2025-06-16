import asyncio
import uuid
from typing import List, Optional, Dict, Any
import ssl
import socket
import OpenSSL.SSL

from .base_scanner import BaseScanner
from ..types.models import ScanInput, Finding, Severity, OwaspCategory

class SSLTLSConfigurationAuditScanner(BaseScanner):
    """
    A scanner module for auditing SSL/TLS configurations.
    """

    async def _perform_scan(self, target: str, options: Dict) -> List[Finding]:
        """
        Asynchronously connects to the target's SSL/TLS port and audits its configuration.

        Args:
            target: The target URL for the scan.
            options: Additional options for the scan.

        Returns:
            A list of Finding objects for detected SSL/TLS configuration issues.
        """
        findings: List[Finding] = []
        target_url = target
        host = target_url.split('//')[-1].split('/')[0].split(':')[0] # Extract host from URL
        port = 443

        print(f"[*] Starting SSL/TLS Configuration Audit for {host}:{port}...")

        try:
            # Create an SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE # We want to inspect even invalid certs

            # Establish connection
            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    # Get certificate chain
                    cert_chain = ssock.getpeercerts(binary_form=True)
                    if not cert_chain:
                        findings.append(
                            Finding(
                                id=str(uuid.uuid4()),
                                vulnerability_type="Missing SSL/TLS Certificate",
                                description="No SSL/TLS certificate was presented by the server.",
                                severity=Severity.CRITICAL,
                                affected_url=target_url,
                                remediation="Install a valid SSL/TLS certificate on the server.",
                                owasp_category=OwaspCategory.A02_CRYPTOGRAPHIC_FAILURES,
                                proof={"details": "No certificate found."}
                            )
                        )
                    else:
                        # Check for self-signed/expired certs (basic check)
                        for i, cert_bytes in enumerate(cert_chain):
                            cert = OpenSSL.SSL.load_certificate(OpenSSL.SSL.FILETYPE_ASN1, cert_bytes)
                            # Check expiry
                            if cert.has_expired():
                                findings.append(
                                    Finding(
                                        id=str(uuid.uuid4()),
                                        vulnerability_type="Expired SSL/TLS Certificate",
                                        description=f"SSL/TLS certificate in chain (index {i}) has expired.",
                                        severity=Severity.HIGH,
                                        affected_url=target_url,
                                        remediation="Renew the expired SSL/TLS certificate.",
                                        owasp_category=OwaspCategory.A02_CRYPTOGRAPHIC_FAILURES,
                                        proof={"details": f"Certificate expired on {cert.get_notAfter().decode()}"}
                                    )
                                )
                            # Check if self-signed (simplistic: issuer == subject and not in a common CA list)
                            if cert.get_subject().get_components() == cert.get_issuer().get_components() and i == 0: # Only check leaf cert for self-signed
                                findings.append(
                                    Finding(
                                        id=str(uuid.uuid4()),
                                        vulnerability_type="Self-Signed SSL/TLS Certificate",
                                        description="The server is using a self-signed SSL/TLS certificate, which is not trusted by default browsers.",
                                        severity=Severity.MEDIUM,
                                        affected_url=target_url,
                                        remediation="Obtain and install a certificate from a trusted Certificate Authority (CA).",
                                        owasp_category=OwaspCategory.A02_CRYPTOGRAPHIC_FAILURES,
                                        proof={"details": "Issuer and Subject are identical (self-signed)."}
                                    )
                                )

                    # Check for weak ciphers (requires more detailed logic with ssl.get_ciphers() and known weak lists)
                    # This is a very basic placeholder for demonstration.
                    # A real audit would iterate through supported ciphers and compare against a blacklist/whitelist.
                    try:
                        # Get the cipher being used for the current connection
                        current_cipher = ssock.cipher()
                        if current_cipher and ("RC4" in current_cipher[0] or "3DES" in current_cipher[0]):
                            findings.append(
                                Finding(
                                    id=str(uuid.uuid4()),
                                    vulnerability_type="Weak SSL/TLS Cipher Used",
                                    description=f"The server is using a weak SSL/TLS cipher suite: {current_cipher[0]}.",
                                    severity=Severity.HIGH,
                                    affected_url=target_url,
                                    remediation="Configure the web server to use strong, modern cipher suites only.",
                                    owasp_category=OwaspCategory.A02_CRYPTOGRAPHIC_FAILURES,
                                    proof={"details": f"Weak cipher: {current_cipher[0]} detected."}
                                )
                            )
                    except Exception as e:
                        print(f"Could not retrieve current cipher: {e}")

                    # Check for missing HSTS deployment (already handled by SecurityHeadersAnalyzer)
                    # This scanner focuses on the TLS handshake and certificate aspects.

        except (socket.error, ssl.SSLError) as e:
            findings.append(
                Finding(
                    id=str(uuid.uuid4()),
                    vulnerability_type="SSL/TLS Connection Error",
                    description=f"Could not establish SSL/TLS connection to {host}:{port}: {e}. This might indicate an issue with SSL/TLS setup or an unreachable host.",
                    severity=Severity.HIGH if isinstance(e, ssl.SSLError) else Severity.MEDIUM,
                    affected_url=target_url,
                    remediation="Ensure SSL/TLS is properly configured on the server and the port is open.",
                    owasp_category=OwaspCategory.A05_SECURITY_MISCONFIGURATION,
                    proof={"details": str(e)}
                )
            )
        except Exception as e:
            print(f"An unexpected error occurred during SSL/TLS audit of {host}:{port}: {e}")

        print(f"[*] Finished SSL/TLS Configuration Audit for {host}:{port}.")
        return findings 