from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Replace with your actual database URL from environment variables for production
DATABASE_URL = "postgresql://user:password@db/nightingale_db"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)