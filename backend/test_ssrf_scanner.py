# -*- coding: utf-8 -*-
import asyncio
import logging
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.scanners.ssrf_scanner import SsrfScanner
from backend.config_types.models import ScanInput

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def test_ssrf_scanner(target="http://localhost:8000"):
    try:
        scanner = SsrfScanner()
        logger.info("Testing SSRF Scanner")
        result = await scanner.scan(ScanInput(target=target, options={}))
        logger.info(f"Scan completed with {len(result)} findings")
        for finding in result:
            logger.info(f"Finding: {finding.get('title', 'No title')} - Severity: {finding.get('severity', 'Unknown')}")
            logger.info(f"Evidence: {finding.get('evidence', {})}")
        return True
    except Exception as e:
        logger.error(f"Error testing SSRF Scanner: {str(e)}", exc_info=True)
        return False

async def main():
    success = await test_ssrf_scanner()
    print("\nTest Summary:")
    print("-" * 50)
    status = "PASSED" if success else "FAILED"
    print(f"SSRF Scanner: {status}")

if __name__ == "__main__":
    asyncio.run(main()) 
