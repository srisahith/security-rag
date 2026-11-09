import os
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime

# Get the DATABASE_URL from your .env file
SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL")

engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class ScanRecord(Base):
    __tablename__ = "scans"
    id = Column(Integer, primary_key=True, index=True)
    target_url = Column(String, index=True)
    payload_used = Column(String)
    status = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)

# Create the table in Postgres (runs when the file is imported)
Base.metadata.create_all(bind=engine)