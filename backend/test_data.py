from datetime import datetime
from sqlalchemy.orm import Session
from app.database import SessionLocal, engine
from app.models.asset_models import DiscoveredAsset
from app.models.vulnerability_models import VulnerabilityData, VulnerabilityMitigation, ThreatIntelData

def create_test_data():
    db = SessionLocal()

    try:
        # Create a test asset
        asset = DiscoveredAsset(
            asset_type="domain",
            identifier="example.com",
            asset_metadata={"whois": {"registrar": "Example Registrar"}},
            risk_score=7.5
        )
        db.add(asset)
        db.flush()  # Get the ID without committing

        # Create a vulnerability
        vuln = VulnerabilityData(
            source="test_scanner",
            title="Test Vulnerability",
            description="This is a test vulnerability",
            severity=8.0,
            cvss_score=8.0,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            raw_data={"scanner_output": "Test output"},
            asset_id=asset.id
        )
        db.add(vuln)
        db.flush()

        # Create a mitigation
        mitigation = VulnerabilityMitigation(
            vulnerability_id=vuln.id,
            recommendation="Apply security patch",
            priority=1,
            estimated_effort="Low"
        )
        db.add(mitigation)

        # Create threat intel
        intel = ThreatIntelData(
            vulnerability_id=vuln.id,
            source="test_intel",
            threat_type="exploit",
            confidence_score=0.9,
            raw_data={"intel_details": "Test intel data"}
        )
        db.add(intel)

        # Commit all changes
        db.commit()
        print("Test data created successfully!")

        # Verify the relationships
        asset = db.query(DiscoveredAsset).first()
        # Verify the data was created
        asset_check = db.query(DiscoveredAsset).first()
        if asset_check:
            print("\nAsset:", asset_check.identifier)
            print("Vulnerabilities:", [v.title for v in asset_check.vulnerabilities])

        vuln_check = db.query(VulnerabilityData).first()
        if vuln_check:
            print("\nVulnerability:", vuln_check.title)
            if vuln_check.asset:
                print("Asset:", vuln_check.asset.identifier)
            print("Mitigations:", [m.recommendation for m in vuln_check.mitigations])
            print("Threat Intel:", [t.threat_type for t in vuln_check.intel_data])

    except Exception as e:
        print(f"Error: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == '__main__':
    create_test_data()