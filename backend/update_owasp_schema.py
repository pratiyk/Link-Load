"""Add missing columns to OWASP scan tables in Supabase"""
import os
from dotenv import load_dotenv
from sqlalchemy import create_engine, text

load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")

engine = create_engine(DATABASE_URL)

print("Adding missing columns to owasp_scans table...")
try:
    with engine.connect() as conn:
        # Add missing columns
        columns_to_add = [
            "ALTER TABLE owasp_scans ADD COLUMN IF NOT EXISTS critical_count INTEGER DEFAULT 0",
            "ALTER TABLE owasp_scans ADD COLUMN IF NOT EXISTS high_count INTEGER DEFAULT 0",
            "ALTER TABLE owasp_scans ADD COLUMN IF NOT EXISTS medium_count INTEGER DEFAULT 0",
            "ALTER TABLE owasp_scans ADD COLUMN IF NOT EXISTS low_count INTEGER DEFAULT 0"
        ]
        
        for sql in columns_to_add:
            conn.execute(text(sql))
            print(f"✅ Executed: {sql}")
        
        conn.commit()
        print("✅ Schema updated successfully!")
        print("\n⚠️  Remember to reload Supabase schema cache in the dashboard!")
        
except Exception as e:
    print(f"❌ Error updating schema: {e}")
    import traceback
    traceback.print_exc()
