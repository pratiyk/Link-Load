"""Unit tests for MITRE ATT&CK mapping functionality."""
import pytest
from app.services.intelligence_mapping.mitre_mapper import MITREMapper
from app.models.threat_intel_models import (
    MITRETechnique,
    MITRETactic,
    CAPEC
)
from typing import Dict, Any
import json

@pytest.mark.anyio("asyncio")
async def test_semantic_mapping(mitre_mapper, db_session):
    """Test semantic similarity-based technique mapping."""
    # Prepare test data
    test_description = """
    The application is vulnerable to SQL injection attacks in the login form.
    Attackers can bypass authentication by injecting malicious SQL queries.
    """
    
    # Create test technique
    test_technique = MITRETechnique(
        technique_id="T1190",
        name="SQL Injection",
        description="Adversaries may attempt to bypass authentication or access data by exploiting SQL injection vulnerabilities."
    )
    db_session.add(test_technique)
    db_session.commit()
    
    # Run mapping
    mapping_results = await mitre_mapper.map_vulnerability(test_description)
    
    assert mapping_results is not None
    assert len(mapping_results["techniques"]) > 0
    assert any(t["technique_id"] == "T1190" for t in mapping_results["techniques"])
    assert all(0 <= t["confidence"] <= 1 for t in mapping_results["techniques"])

@pytest.mark.anyio("asyncio")
async def test_ensemble_mapping(mitre_mapper, db_session):
    """Test multi-algorithm ensemble mapping approach."""
    # Prepare test data
    test_vuln = {
        "description": "Critical buffer overflow vulnerability allowing remote code execution",
        "cve_id": "CVE-2023-1234"
    }
    
    # Add test techniques
    techniques = [
        MITRETechnique(
            technique_id="T1588.005",
            name="Buffer Overflow Exploit",
            description="Adversaries may exploit buffer overflow vulnerabilities for code execution."
        ),
        MITRETechnique(
            technique_id="T1190",
            name="Exploit Public-Facing Application",
            description="Adversaries may attempt to take advantage of vulnerabilities in public-facing applications."
        )
    ]
    db_session.add_all(techniques)
    db_session.commit()
    
    # Run mapping
    results = await mitre_mapper.map_vulnerability(
        test_vuln["description"],
        test_vuln["cve_id"]
    )
    
    # Verify results
    assert isinstance(results, dict)
    assert "techniques" in results
    assert "ttps" in results
    assert "capec_patterns" in results
    assert "confidence_explanation" in results
    
    # Check confidence scores
    assert all(0 <= t["confidence"] <= 1 for t in results["techniques"])
    assert len(results["techniques"]) > 0

@pytest.mark.anyio("asyncio")
async def test_ttp_relationship_mapping(mitre_mapper, db_session):
    """Test TTP (Tactics, Techniques, Procedures) relationship mapping."""
    # Create test data
    tactic = MITRETactic(
        tactic_id="TA0001",
        name="Initial Access"
    )
    technique = MITRETechnique(
        technique_id="T1190",
        name="Exploit Public-Facing Application",
        description="Adversaries may attempt to take advantage of vulnerabilities."
    )
    technique.tactics.append(tactic)
    
    db_session.add(tactic)
    db_session.add(technique)
    db_session.commit()
    
    # Test mapping
    results = await mitre_mapper.map_vulnerability(
        "A vulnerability in the public web interface allows remote code execution"
    )
    
    # Verify TTP relationships
    assert "ttps" in results
    assert len(results["ttps"]) > 0
    ttp = results["ttps"][0]
    assert "tactic" in ttp
    assert "technique" in ttp
    assert "procedure" in ttp
    assert ttp["tactic"] == "Initial Access"

@pytest.mark.anyio("asyncio")
async def test_capec_correlation(mitre_mapper, db_session):
    """Test CAPEC pattern correlation with MITRE techniques."""
    # Create test data
    technique = MITRETechnique(
        technique_id="T1190",
        name="Exploit Public-Facing Application"
    )
    capec = CAPEC(
        pattern_id="CAPEC-66",
        name="SQL Injection",
        description="SQL injection attacks",
        typical_likelihood="High",
        mitre_technique_ids=["T1190"]
    )
    
    db_session.add(technique)
    db_session.add(capec)
    db_session.commit()
    
    # Test mapping
    results = await mitre_mapper.map_vulnerability(
        "SQL injection vulnerability in login form"
    )
    
    # Verify CAPEC correlations
    assert "capec_patterns" in results
    assert len(results["capec_patterns"]) > 0
    pattern = results["capec_patterns"][0]
    assert pattern["pattern_id"] == "CAPEC-66"
    assert "likelihood" in pattern
    assert "confidence" in pattern

@pytest.mark.anyio("asyncio")
async def test_confidence_scoring(mitre_mapper):
    """Test confidence scoring and explanation generation."""
    # Test mapping with high-confidence match
    results = await mitre_mapper.map_vulnerability(
        "Clear evidence of SQL injection vulnerability in authentication module"
    )
    
    # Verify confidence explanation
    explanation = results["confidence_explanation"]
    assert "overall_confidence" in explanation
    assert "matching_methods" in explanation
    assert "decision_factors" in explanation
    
    # Check confidence score properties
    assert 0 <= explanation["overall_confidence"] <= 1
    assert isinstance(explanation["matching_methods"], dict)
    assert len(explanation["decision_factors"]) > 0

def test_technique_caching(mitre_mapper):
    """Test MITRE data caching functionality."""
    # Verify cache initialization
    assert len(mitre_mapper.techniques_cache) > 0
    assert len(mitre_mapper.tactics_cache) > 0
    
    # Check cache content
    for tech_id, technique in mitre_mapper.techniques_cache.items():
        assert isinstance(technique, MITRETechnique)
        assert technique.technique_id == tech_id

@pytest.mark.anyio("asyncio")
async def test_error_handling(mitre_mapper):
    """Test error handling in mapping process."""
    # Test with invalid input
    with pytest.raises(ValueError):
        await mitre_mapper.map_vulnerability(None)
    
    # Test with empty description
    results = await mitre_mapper.map_vulnerability("")
    assert results["techniques"] == []
    assert results["confidence_explanation"]["overall_confidence"] == 0