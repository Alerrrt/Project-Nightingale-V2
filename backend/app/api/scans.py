# backend/app/api/scans.py
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from ..database import models, session
from ..tasks.scan_tasks import run_full_scan
from ..schemas.scan import ScanCreate, ScanResponse # Pydantic schemas

router = APIRouter()

def get_db():
    db = session.SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.post("/scans/", response_model=ScanResponse)
def create_scan(scan: ScanCreate, db: Session = Depends(get_db)):
    # 1. Find or create the target domain
    target = db.query(models.Target).filter(models.Target.domain == scan.domain).first()
    if not target:
        target = models.Target(domain=scan.domain)
        db.add(target)
        db.commit()
        db.refresh(target)

    # 2. Create a new scan record in the database
    new_scan = models.Scan(target_id=target.id)
    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)

    # 3. Dispatch the scan job to the Celery worker
    run_full_scan.delay(new_scan.id)
    
    return new_scan