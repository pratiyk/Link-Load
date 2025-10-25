import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from contextlib import contextmanager
from typing import Generator
from dotenv import load_dotenv

load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:password@localhost:5432/linkload")

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
    echo=False
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db() -> Generator[Session, None, None]:
    """Dependency for FastAPI routes"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@contextmanager
def get_db_context():
    """Context manager for background tasks"""
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

def init_db():
    """Initialize database tables"""
    try:
        from app.models.user import User, RevokedToken
        from app.models.attack_surface_models import AttackSurfaceScan, DiscoveredAsset
        from app.models.vulnerability_models import VulnerabilityData, VulnerabilityMitigation, ThreatIntelData
        
        # Import MITRE models to ensure tables are created
        try:
            from app.models.threat_intel_models import MITRETactic, MITRETechnique
            from app.models.mitre_models import MITRESubTechnique, Procedure, CAPEC
            from app.models.associations import (
                vulnerability_technique_association,
                technique_tactic_association,
                technique_capec_association
            )
        except Exception as e:
            # If MITRE models fail to import, log but continue
            print(f"Warning: Could not import MITRE models: {e}")
        
        Base.metadata.create_all(bind=engine)
    except Exception as e:
        print(f"Error initializing database: {e}")
        # Continue anyway - tables may already exist
        pass
