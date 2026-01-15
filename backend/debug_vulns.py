#!/usr/bin/env python3
"""Debug vulnerability insertion issues"""
import sys
import asyncio
from app.database.supabase_client import supabase

def check_schema():
    """Check table schema"""
    try:
        # Get one record to see column names
        result = supabase.admin.table('owasp_vulnerabilities').select('*').limit(1).execute()
        if result.data:
            print(f"Table columns: {list(result.data[0].keys())}")
        else:
            print("No data in table yet")
            
        # Try to get table info directly
        print("\n=== Checking allowed_columns filter in insert_vulnerabilities ===")
        allowed = {
            "scan_id",
            "title",
            "description",
            "severity",
            "cvss_score",
            "location",
            "recommendation",
            "mitre_techniques",
            "scanner_source",
            "scanner_id",
            "discovered_at"
        }
        print(f"Currently filtering to: {allowed}")
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    check_schema()
