from typing import List, Optional
import asyncio
import httpx
from uuid import UUID
from celery import Celery
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError

from .db import SessionLocal
from .models import Scan, Detection
from .modules import discover_modules, ScanModule
from .broadcast import broadcast_manager

# Initialize Celery
celery = Celery('scanner')
celery.config_from_object('celeryconfig')

async def fetch_url(url: str) -> Optional[httpx.Response]:
    """Fetch URL using httpx.AsyncClient with error handling."""
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, follow_redirects=True)
            return response
    except httpx.RequestError as e:
        print(f"Error fetching URL {url}: {str(e)}")
        return None

async def run_module_analysis(
    module: ScanModule,
    response: httpx.Response,
    db: Session,
    scan_id: UUID
) -> None:
    """Run a single module's analysis and save results to database."""
    try:
        detections = await module.analyze(response)
        for detection in detections:
            # Create database record
            db_detection = Detection(
                scan_id=scan_id,
                module_id=module.id,
                description=detection.description,
                details=detection.details,
                severity="medium"  # Could be made configurable per module
            )
            db.add(db_detection)
            db.commit()
            
            # Broadcast detection event
            await broadcast_manager.broadcast_scan_event(
                str(scan_id),
                {
                    "url": str(response.url),
                    "module_id": module.id,
                    "severity": db_detection.severity,
                    "snippet": detection.details,
                    "description": detection.description
                }
            )
            
    except Exception as e:
        print(f"Error in module {module.id}: {str(e)}")
        db.rollback()

@celery.task(bind=True, max_retries=3)
def run_scan(self, url: str, scan_id: UUID) -> None:
    """Celery task to run passive scan on a URL."""
    db = SessionLocal()
    try:
        # Update scan status to running
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            raise ValueError(f"Scan {scan_id} not found")
        
        scan.status = "running"
        db.commit()

        # Fetch URL
        response = asyncio.run(fetch_url(url))
        if not response:
            scan.status = "failed"
            db.commit()
            return

        # Load and run all modules concurrently
        modules = discover_modules()
        tasks = [
            run_module_analysis(module, response, db, scan_id)
            for module in modules
        ]
        asyncio.run(asyncio.gather(*tasks))

        # Update scan status to completed
        scan.status = "completed"
        db.commit()

    except SQLAlchemyError as e:
        db.rollback()
        print(f"Database error: {str(e)}")
        self.retry(exc=e, countdown=60)
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        scan.status = "failed"
        db.commit()
    finally:
        db.close() 