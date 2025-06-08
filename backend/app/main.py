from fastapi import FastAPI
from .database import models, session
from .api import scans

# Create database tables if they don't exist
models.Base.metadata.create_all(bind=session.engine)

app = FastAPI(title="Nightingale V2 API")

# Include the API router for scan-related endpoints
app.include_router(scans.router, prefix="/api", tags=["scans"])

@app.get("/")
def read_root():
    return {"message": "Welcome to the Nightingale V2 API"}