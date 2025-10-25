"""Create OWASP scan tables in Supabase"""
import os
from dotenv import load_dotenv
from sqlalchemy import create_engine, text

load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")

engine = create_engine(DATABASE_URL)

print("Creating OWASP scanning tables...")
try:
    with engine.connect() as conn:
        # Create owasp_scans table
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS owasp_scans (
                scan_id VARCHAR(50) PRIMARY KEY,
                user_id VARCHAR(50) NOT NULL,
                target_url VARCHAR(2048) NOT NULL,
                status VARCHAR(50) NOT NULL DEFAULT 'pending',
                progress INTEGER DEFAULT 0,
                current_stage VARCHAR(255) DEFAULT 'Initializing',
                started_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                completed_at TIMESTAMP WITH TIME ZONE,
                scan_types JSONB DEFAULT '[]'::jsonb,
                options JSONB DEFAULT '{}'::jsonb,
                risk_score FLOAT,
                risk_level VARCHAR(50),
                critical_count INTEGER DEFAULT 0,
                high_count INTEGER DEFAULT 0,
                medium_count INTEGER DEFAULT 0,
                low_count INTEGER DEFAULT 0,
                ai_analysis JSONB,
                mitre_mapping JSONB,
                remediation_strategies JSONB,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            )
        """))
        
        # Create indexes
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_owasp_scans_user_id ON owasp_scans(user_id)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_owasp_scans_status ON owasp_scans(status)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_owasp_scans_created_at ON owasp_scans(created_at)"))
        
        # Create owasp_vulnerabilities table
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS owasp_vulnerabilities (
                vulnerability_id SERIAL PRIMARY KEY,
                scan_id VARCHAR(50) NOT NULL REFERENCES owasp_scans(scan_id) ON DELETE CASCADE,
                title VARCHAR(512) NOT NULL,
                description TEXT,
                severity VARCHAR(50) NOT NULL,
                cvss_score FLOAT,
                location VARCHAR(2048),
                recommendation TEXT,
                mitre_techniques JSONB DEFAULT '[]'::jsonb,
                scanner_source VARCHAR(100),
                scanner_id VARCHAR(256),
                discovered_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            )
        """))
        
        # Create indexes for vulnerabilities
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_owasp_vulnerabilities_scan_id ON owasp_vulnerabilities(scan_id)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_owasp_vulnerabilities_severity ON owasp_vulnerabilities(severity)"))
        
        # Create audit log table
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS scan_audit_log (
                audit_id SERIAL PRIMARY KEY,
                scan_id VARCHAR(50) NOT NULL REFERENCES owasp_scans(scan_id) ON DELETE CASCADE,
                action VARCHAR(100) NOT NULL,
                old_status VARCHAR(50),
                new_status VARCHAR(50),
                details JSONB,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            )
        """))
        
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_scan_audit_log_scan_id ON scan_audit_log(scan_id)"))
        
        conn.commit()
        print("✅ Tables created successfully!")
        
except Exception as e:
    print(f"❌ Error creating tables: {e}")
    import traceback
    traceback.print_exc()
