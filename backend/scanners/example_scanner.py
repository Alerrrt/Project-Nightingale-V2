from typing import List, Dict, Any
from backend.scanners.base_scanner import BaseScanner, Finding
from backend.scanners.scanner_registry import ScannerRegistry

class ExampleScanner(BaseScanner):
    """
    Example scanner module demonstrating the registration pattern.
    """
    async def _perform_scan(self, target: str, options: Dict) -> List[Finding]:
        """
        Perform the scan and return findings.

        Args:
            target: The target for the scan.
            options: Additional options for the scan.

        Returns:
            A list of findings.
        """
        # Example implementation
        findings = []
        # Add your scanning logic here, using 'target' and 'options'
        # Example: print(f"Scanning {target} with options {options}")
        return findings

def register(scanner_registry: ScannerRegistry) -> None:
    """
    Register this scanner with the scanner registry.

    Args:
        scanner_registry: The scanner registry instance.
    """
    scanner_registry.register("example", ExampleScanner) 