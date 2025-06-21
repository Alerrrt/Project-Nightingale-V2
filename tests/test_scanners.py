import asyncio
import logging
import os
import sys

# Add the parent directory to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.scanners.api_security_scanner import APISecurityScanner
from backend.scanners.authentication_scanner import AuthenticationScanner
from backend.scanners.broken_access_control_scanner import BrokenAccessControlScanner
from backend.types.models import ScanInput

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def test_scanner(scanner_class, target="http://localhost:8000"):
    try:
        scanner = scanner_class()
        logger.info(f"Testing scanner: {scanner_class.__name__}")
        
        # Run the scan
        result = await scanner.scan(ScanInput(target=target, options={}))
        
        # Log results
        logger.info(f"Scan completed with {len(result)} findings")
        for finding in result:
            logger.info(f"Finding: {finding.get('title', 'No title')} - Severity: {finding.get('severity', 'Unknown')}")
            
        return True
    except Exception as e:
        logger.error(f"Error testing {scanner_class.__name__}: {str(e)}", exc_info=True)
        return False

async def main():
    # Test multiple scanners
    scanners = [
        APISecurityScanner,
        AuthenticationScanner,
        BrokenAccessControlScanner
    ]
    
    results = []
    for scanner_class in scanners:
        success = await test_scanner(scanner_class)
        results.append((scanner_class.__name__, success))
    
    # Print summary
    print("\nTest Summary:")
    print("-" * 50)
    for scanner_name, success in results:
        status = "PASSED" if success else "FAILED"
        print(f"{scanner_name}: {status}")

if __name__ == "__main__":
    asyncio.run(main()) 