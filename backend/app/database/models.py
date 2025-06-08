# backend/app/database/models.py
from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey, Text, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
import datetime

Base = declarative_base()

class Target(Base):
    __tablename__ = "targets"
    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String, unique=True, index=True, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    scans = relationship("Scan", back_populates="target")

class Scan(Base):
    __tablename__ = "scans"
    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"))
    status = Column(String, default="PENDING") # PENDING, RUNNING, COMPLETED, FAILED
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    
    target = relationship("Target", back_populates="scans")
    vulnerabilities = relationship("Vulnerability", back_populates="scan")

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    host = Column(String, index=True)
    name = Column(String) # e.g., "SQL Injection"
    severity = Column(String, index=True) # e.g., "CRITICAL", "HIGH"
    description = Column(Text)
    details = Column(JSON) # To store the raw Nuclei output

    scan = relationship("Scan", back_populates="vulnerabilities")