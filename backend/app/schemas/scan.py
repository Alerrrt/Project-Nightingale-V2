from pydantic import BaseModel
from datetime import datetime
from typing import Optional

# Schema for creating a new scan (request)
class ScanCreate(BaseModel):
    domain: str

# Schema for the scan response (what the API returns)
class ScanResponse(BaseModel):
    id: int
    target_id: int
    status: str
    created_at: datetime

    class Config:
        orm_mode = True # This allows Pydantic to read data from ORM models