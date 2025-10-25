"""Reset database tables - drop and recreate"""
import os
from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from app.database import Base

load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")

engine = create_engine(DATABASE_URL)

print("Dropping all tables...")
try:
    # Drop tables that might have conflicts in reverse dependency order
    with engine.connect() as conn:
        # First drop tables with foreign keys
        conn.execute(text("DROP TABLE IF EXISTS threat_intelligence CASCADE"))
        conn.execute(text("DROP TABLE IF EXISTS risk_scores CASCADE"))
        conn.execute(text("DROP TABLE IF EXISTS threat_intel_data CASCADE"))
        conn.execute(text("DROP TABLE IF EXISTS vulnerability_mitigations CASCADE"))
        conn.execute(text("DROP TABLE IF EXISTS vulnerability_findings CASCADE"))
        conn.execute(text("DROP TABLE IF EXISTS vulnerabilities CASCADE"))
        
        # Drop association tables
        conn.execute(text("DROP TABLE IF EXISTS technique_capec_association CASCADE"))
        conn.execute(text("DROP TABLE IF EXISTS technique_tactic_association CASCADE"))
        conn.execute(text("DROP TABLE IF EXISTS vulnerability_technique_association CASCADE"))
        
        # Drop MITRE tables
        conn.execute(text("DROP TABLE IF EXISTS mitre_sub_techniques CASCADE"))
        conn.execute(text("DROP TABLE IF EXISTS procedures CASCADE"))
        conn.execute(text("DROP TABLE IF EXISTS capec_patterns CASCADE"))
        conn.execute(text("DROP TABLE IF EXISTS mitre_techniques CASCADE"))
        conn.execute(text("DROP TABLE IF EXISTS mitre_tactics CASCADE"))
        
        # Drop assets and related
        conn.execute(text("DROP TABLE IF EXISTS discovered_assets CASCADE"))
        conn.execute(text("DROP TABLE IF EXISTS attack_surface_scans CASCADE"))
        
        conn.commit()
    print("Tables dropped successfully")
except Exception as e:
    print(f"Error dropping tables: {e}")

print("\nRecreating tables...")
try:
    # Import all models to register them
    from app.models.user import User, RevokedToken
    from app.models.attack_surface_models import AttackSurfaceScan, DiscoveredAsset
    from app.models.vulnerability_models import VulnerabilityData, VulnerabilityMitigation, ThreatIntelData, VulnerabilityFinding
    
    try:
        from app.models.threat_intel_models import MITRETactic, MITRETechnique, ThreatIntelligence, RiskScore
        from app.models.mitre_models import MITRESubTechnique, Procedure, CAPEC
        from app.models.associations import (
            vulnerability_technique_association,
            technique_tactic_association,
            technique_capec_association
        )
    except Exception as e:
        print(f"Warning: Could not import MITRE models: {e}")
    
    Base.metadata.create_all(bind=engine)
    print("Tables created successfully")
except Exception as e:
    print(f"Error creating tables: {e}")
    import traceback
    traceback.print_exc()
