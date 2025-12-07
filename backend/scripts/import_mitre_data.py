#!/usr/bin/env python
"""
Import MITRE ATT&CK Framework data into the database.

This script fetches the latest MITRE ATT&CK data from the official CTI repository
and populates the database tables for tactics, techniques, and CAPEC patterns.

No API key required - uses public GitHub repository.
"""
import asyncio
import aiohttp
import json
import sys
import os

# Add backend to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.database.supabase_client import supabase

# MITRE ATT&CK data URLs (official repository - no API key needed)
MITRE_ENTERPRISE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
MITRE_MOBILE_URL = "https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json"
MITRE_ICS_URL = "https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json"
CAPEC_URL = "https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix-capec.json"


async def fetch_json(session: aiohttp.ClientSession, url: str) -> dict:
    """Fetch JSON data from URL."""
    print(f"Fetching: {url}")
    async with session.get(url) as response:
        if response.status != 200:
            print(f"  WARNING: Failed to fetch {url} (status {response.status})")
            return {"objects": []}
        # Use content_type=None to ignore MIME type since GitHub raw returns text/plain
        text = await response.text()
        data = json.loads(text)
        print(f"  Downloaded {len(data.get('objects', []))} objects")
        return data


def extract_technique_id(external_refs: list) -> str | None:
    """Extract MITRE technique ID from external references."""
    for ref in external_refs:
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def extract_capec_id(external_refs: list) -> str | None:
    """Extract CAPEC pattern ID from external references."""
    for ref in external_refs:
        if ref.get("source_name") == "capec":
            return ref.get("external_id")
    return None


def upsert_tactic(tactic_id: str, name: str, description: str, url: str, matrix: str):
    """Insert or update a tactic in Supabase."""
    data = {
        "tactic_id": tactic_id,
        "name": name,
        "description": description[:10000] if description else "",  # Limit description length
        "url": url,
        "matrix": matrix
    }
    try:
        supabase.admin.table("mitre_tactics").upsert(data, on_conflict="tactic_id").execute()
        return True
    except Exception as e:
        print(f"    Error upserting tactic {tactic_id}: {e}")
        return False


def upsert_technique(technique_id: str, name: str, description: str, detection: str, 
                     url: str, data_sources: list, platforms: list, permissions: list):
    """Insert or update a technique in Supabase."""
    data = {
        "technique_id": technique_id,
        "name": name,
        "description": description[:10000] if description else "",
        "detection": detection[:10000] if detection else "",
        "url": url,
        "data_sources": data_sources,
        "platforms": platforms,
        "permissions_required": permissions
    }
    try:
        supabase.admin.table("mitre_techniques").upsert(data, on_conflict="technique_id").execute()
        return True
    except Exception as e:
        print(f"    Error upserting technique {technique_id}: {e}")
        return False


def upsert_sub_technique(sub_technique_id: str, parent_id: str, name: str, 
                         description: str, detection: str, url: str, data_sources: list):
    """Insert or update a sub-technique in Supabase."""
    data = {
        "sub_technique_id": sub_technique_id,
        "parent_technique_id": parent_id,
        "name": name,
        "description": description[:10000] if description else "",
        "detection": detection[:10000] if detection else "",
        "url": url,
        "data_sources": data_sources
    }
    try:
        supabase.admin.table("mitre_sub_techniques").upsert(data, on_conflict="sub_technique_id").execute()
        return True
    except Exception as e:
        print(f"    Error upserting sub-technique {sub_technique_id}: {e}")
        return False


def upsert_capec(pattern_id: str, name: str, description: str, likelihood: str,
                 severity: str, prerequisites: list, mitigations: list, technique_ids: list):
    """Insert or update a CAPEC pattern in Supabase."""
    data = {
        "pattern_id": pattern_id,
        "name": name,
        "description": description[:10000] if description else "",
        "likelihood": likelihood,
        "typical_likelihood": likelihood,
        "typical_severity": severity,
        "prerequisites": prerequisites,
        "mitigations": mitigations,
        "mitre_technique_ids": technique_ids
    }
    try:
        supabase.admin.table("capec_patterns").upsert(data, on_conflict="pattern_id").execute()
        return True
    except Exception as e:
        print(f"    Error upserting CAPEC {pattern_id}: {e}")
        return False


def link_technique_tactic(technique_id: str, tactic_id: str):
    """Link a technique to a tactic."""
    data = {
        "technique_id": technique_id,
        "tactic_id": tactic_id
    }
    try:
        # Check if link already exists
        existing = supabase.admin.table("technique_tactic_association").select("*").eq(
            "technique_id", technique_id
        ).eq("tactic_id", tactic_id).execute()
        
        if not existing.data:
            supabase.admin.table("technique_tactic_association").insert(data).execute()
        return True
    except Exception as e:
        # Ignore duplicate key errors
        if "duplicate" not in str(e).lower():
            print(f"    Error linking {technique_id} to {tactic_id}: {e}")
        return False


async def import_mitre_data():
    """Import all MITRE ATT&CK data into database."""
    print("\n" + "="*60)
    print("MITRE ATT&CK Data Import Script")
    print("="*60)
    print("\nNo API key required - using public MITRE CTI repository\n")
    
    try:
        async with aiohttp.ClientSession() as http_session:
            # Fetch all data sources
            print("\n--- Fetching MITRE ATT&CK Data ---")
            enterprise_data = await fetch_json(http_session, MITRE_ENTERPRISE_URL)
            
            # Parse tactics first
            print("\n--- Importing Tactics ---")
            tactics_count = 0
            tactic_map = {}  # shortname -> tactic_id
            
            for obj in enterprise_data.get("objects", []):
                if obj.get("type") == "x-mitre-tactic":
                    shortname = obj.get("x_mitre_shortname", "")
                    tactic_id = shortname or obj.get("id", "").split("--")[-1]
                    name = obj.get("name", "Unknown")
                    
                    if upsert_tactic(
                        tactic_id=tactic_id,
                        name=name,
                        description=obj.get("description", ""),
                        url=f"https://attack.mitre.org/tactics/{tactic_id}/",
                        matrix="enterprise"
                    ):
                        tactics_count += 1
                    
                    tactic_map[shortname] = tactic_id
            
            print(f"  Imported {tactics_count} tactics")
            
            # Parse techniques - TWO PASSES to ensure parent techniques exist before sub-techniques
            print("\n--- Importing Techniques (Pass 1: Main Techniques) ---")
            techniques_count = 0
            sub_techniques_list = []  # Store sub-techniques for second pass
            
            for obj in enterprise_data.get("objects", []):
                if obj.get("type") == "attack-pattern":
                    ext_refs = obj.get("external_references", [])
                    technique_id = extract_technique_id(ext_refs)
                    
                    if not technique_id:
                        continue
                    
                    # Check if this is a sub-technique
                    is_sub = obj.get("x_mitre_is_subtechnique", False)
                    
                    if is_sub:
                        # Store for second pass
                        sub_techniques_list.append(obj)
                    else:
                        # Main technique
                        if upsert_technique(
                            technique_id=technique_id,
                            name=obj.get("name", "Unknown"),
                            description=obj.get("description", ""),
                            detection=obj.get("x_mitre_detection", ""),
                            url=f"https://attack.mitre.org/techniques/{technique_id}/",
                            data_sources=obj.get("x_mitre_data_sources", []),
                            platforms=obj.get("x_mitre_platforms", []),
                            permissions=obj.get("x_mitre_permissions_required", [])
                        ):
                            techniques_count += 1
                        
                        # Link to tactics
                        kill_chain = obj.get("kill_chain_phases", [])
                        for phase in kill_chain:
                            phase_name = phase.get("phase_name", "")
                            if phase_name in tactic_map:
                                link_technique_tactic(technique_id, tactic_map[phase_name])
            
            print(f"  Imported {techniques_count} techniques")
            
            # Second pass: Import sub-techniques
            print("\n--- Importing Sub-Techniques (Pass 2) ---")
            sub_techniques_count = 0
            
            for obj in sub_techniques_list:
                ext_refs = obj.get("external_references", [])
                technique_id = extract_technique_id(ext_refs)
                
                if not technique_id:
                    continue
                
                parent_id = technique_id.split(".")[0] if "." in technique_id else None
                
                if upsert_sub_technique(
                    sub_technique_id=technique_id,
                    parent_id=parent_id,
                    name=obj.get("name", "Unknown"),
                    description=obj.get("description", ""),
                    detection=obj.get("x_mitre_detection", ""),
                    url=f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
                    data_sources=obj.get("x_mitre_data_sources", [])
                ):
                    sub_techniques_count += 1
            
            print(f"  Imported {sub_techniques_count} sub-techniques")
            
            # Fetch and import CAPEC data
            print("\n--- Importing CAPEC Patterns ---")
            capec_data = await fetch_json(http_session, CAPEC_URL)
            capec_count = 0
            
            for obj in capec_data.get("objects", []):
                if obj.get("type") == "attack-pattern":
                    ext_refs = obj.get("external_references", [])
                    pattern_id = extract_capec_id(ext_refs)
                    
                    if not pattern_id:
                        continue
                    
                    # Extract related MITRE techniques
                    related_techniques = []
                    for ref in ext_refs:
                        if ref.get("source_name") == "mitre-attack":
                            related_techniques.append(ref.get("external_id"))
                    
                    if upsert_capec(
                        pattern_id=pattern_id,
                        name=obj.get("name", "Unknown"),
                        description=obj.get("description", ""),
                        likelihood=obj.get("x_capec_likelihood_of_attack", ""),
                        severity=obj.get("x_capec_typical_severity", ""),
                        prerequisites=obj.get("x_capec_prerequisites", []),
                        mitigations=obj.get("x_capec_mitigations", []),
                        technique_ids=related_techniques
                    ):
                        capec_count += 1
            
            print(f"  Imported {capec_count} CAPEC patterns")
            
        # Print summary
        print("\n" + "="*60)
        print("IMPORT COMPLETE")
        print("="*60)
        
        # Get counts from database
        tactics_result = supabase.admin.table("mitre_tactics").select("tactic_id", count="exact").execute()
        techniques_result = supabase.admin.table("mitre_techniques").select("technique_id", count="exact").execute()
        
        total_tactics = len(tactics_result.data) if tactics_result.data else 0
        total_techniques = len(techniques_result.data) if techniques_result.data else 0
        
        print(f"\nDatabase now contains:")
        print(f"  - {total_tactics} MITRE Tactics")
        print(f"  - {total_techniques} MITRE Techniques")
        print(f"  - {capec_count}+ CAPEC Attack Patterns")
        print("\nMITRE mapping is now ready for use!")
        
    except Exception as e:
        print(f"\nERROR: {e}")
        import traceback
        traceback.print_exc()
        raise


if __name__ == "__main__":
    asyncio.run(import_mitre_data())
