from fastapi import FastAPI, Depends, HTTPException, APIRouter, WebSocket, WebSocketDisconnect
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from typing import List, Optional
from pydantic import BaseModel
from fastapi.security import OAuth2PasswordRequestForm
from datetime import timedelta
import io

from .db import SessionLocal, engine
from .models import Base, User
from .auth import (
    get_current_active_user,
    get_password_hash,
    verify_password,
    create_access_token,
    UserCreate,
    UserResponse,
    Token
)
from .config import settings
from .broadcast import broadcast_manager
from .report import get_scan_report

from fastapi.middleware.cors import CORSMiddleware

# Create database tables
Base.metadata.create_all(bind=engine)

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

router = APIRouter(prefix="/api")

@app.get("/")
def read_root():
    return {"status": "ok", "version": "2.0"}

# Pydantic models
class ScanBase(BaseModel):
    name: str

class ScanCreate(ScanBase):
    pass

class Scan(ScanBase):
    id: int

    class Config:
        orm_mode = True

class ResultBase(BaseModel):
    scan_id: int
    status: str

class ResultCreate(ResultBase):
    pass

class Result(ResultBase):
    id: int

    class Config:
        orm_mode = True

# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Auth endpoints
@app.post("/auth/register", response_model=UserResponse)
async def register(user: UserCreate, db: Session = Depends(get_db)):
    # Check if username exists
    db_user = db.query(User).filter(User.username == user.username).first()
    if db_user:
        raise HTTPException(
            status_code=400,
            detail="Username already registered"
        )
    
    # Check if email exists
    db_user = db.query(User).filter(User.email == user.email).first()
    if db_user:
        raise HTTPException(
            status_code=400,
            detail="Email already registered"
        )
    
    # Create new user
    hashed_password = get_password_hash(user.password)
    db_user = User(
        username=user.username,
        email=user.email,
        hashed_password=hashed_password
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@app.post("/auth/login", response_model=Token)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=settings.jwt_expiration_minutes)
    access_token = create_access_token(
        data={"sub": user.username},
        expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/auth/me", response_model=UserResponse)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user

# Protected scan endpoints
@app.post("/scans/")
async def create_scan(
    scan_data: dict,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    scan = Scan(
        user_id=current_user.id,
        **scan_data
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan

@app.get("/scans/")
async def list_scans(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    scans = db.query(Scan).filter(Scan.user_id == current_user.id).all()
    return scans

@app.get("/scans/{scan_id}")
async def get_scan(
    scan_id: str,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    scan = db.query(Scan).filter(
        Scan.id == scan_id,
        Scan.user_id == current_user.id
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan

@app.get("/scans/{scan_id}/results", response_model=List[Result])
def get_scan_results(scan_id: int, db: Session = Depends(get_db)):
    # Placeholder for actual DB operation
    return [Result(id=1, scan_id=scan_id, status="completed")]

@router.patch("/results/{result_id}", response_model=Result)
def update_result(result_id: int, result: ResultCreate, db: Session = Depends(get_db)):
    # Placeholder for actual DB operation
    return Result(id=result_id, scan_id=result.scan_id, status=result.status)

@app.get("/scans/{scan_id}/report")
async def generate_report(
    scan_id: str,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    try:
        pdf_bytes = await get_scan_report(scan_id, db)
        return StreamingResponse(
            io.BytesIO(pdf_bytes),
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="scan_report_{scan_id}.pdf"'
            }
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# WebSocket endpoint
@app.websocket("/ws/scans/{scan_id}")
async def websocket_endpoint(
    websocket: WebSocket,
    scan_id: str,
    current_user: User = Depends(get_current_active_user)
):
    await broadcast_manager.connect(websocket, scan_id)
    try:
        while True:
            data = await websocket.receive_text()
            # Handle any incoming messages if needed
    except WebSocketDisconnect:
        broadcast_manager.disconnect(websocket, scan_id)

app.include_router(router) 