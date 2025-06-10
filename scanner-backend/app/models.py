from sqlalchemy import Column, String, Integer, ForeignKey, DateTime, Text, Boolean
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid

from .db import Base

def UUIDColumn(*args, **kwargs):
    return Column(String(36), *args, **kwargs)

class User(Base):
    __tablename__ = "users"

    id = UUIDColumn(primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String, unique=True, nullable=False)
    email = Column(String, unique=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    scans = relationship("Scan", back_populates="user")

class Scan(Base):
    __tablename__ = "scans"

    id = UUIDColumn(primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = UUIDColumn(ForeignKey("users.id"))
    url = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    status = Column(String, default="pending")
    detections = relationship("Detection", back_populates="scan")
    user = relationship("User", back_populates="scans")

class Detection(Base):
    __tablename__ = "detections"

    id = Column(Integer, primary_key=True)
    scan_id = UUIDColumn(ForeignKey("scans.id"))
    module_id = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    details = Column(Text)
    severity = Column(String, default="medium")
    notes = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    scan = relationship("Scan", back_populates="detections") 