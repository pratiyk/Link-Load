from datetime import datetime, timedelta
import random
from sqlalchemy.orm import Session
from app.database import SessionLocal, engine
from app.models.asset_models import DiscoveredAsset
from app.models.vulnerability_models import VulnerabilityData, VulnerabilityMitigation, ThreatIntelData

def create_training_data(n_assets=100, n_vulns_per_asset=5):
    """Create realistic training data for ML model development"""
    db = SessionLocal()

    try:
        # Create diverse assets
        asset_types = ["domain", "ip", "webapp", "server", "database", "cloud_resource"]
        assets = []
        
        for i in range(n_assets):
            asset = DiscoveredAsset(
                asset_type=random.choice(asset_types),
                identifier=f"asset_{i}.example.com",
                asset_metadata={
                    "environment": random.choice(["production", "staging", "development"]),
                    "criticality": random.uniform(1, 10),
                    "data_classification": random.choice(["public", "internal", "confidential", "restricted"])
                },
                risk_score=random.uniform(1, 10)
            )
            db.add(asset)
            assets.append(asset)
        
        db.flush()

        # Create vulnerabilities with varying characteristics
        for asset in assets:
            for _ in range(random.randint(1, n_vulns_per_asset)):
                # Generate realistic severity and CVSS
                base_severity = random.uniform(1, 10)
                cvss = min(10, base_severity + random.uniform(-1, 1))
                
                vuln = VulnerabilityData(
                    source=random.choice(["nessus", "qualys", "nuclei", "zap", "manual"]),
                    title=f"Test Vulnerability {random.randint(1000, 9999)}",
                    description="Generated vulnerability for ML training",
                    severity=base_severity,
                    cvss_score=cvss,
                    cvss_vector=f"CVSS:3.1/AV:N/AC:{'L' if random.random() > 0.3 else 'H'}/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    attack_complexity=random.choice(["LOW", "HIGH"]),
                    attack_vector=random.choice(["NETWORK", "ADJACENT", "LOCAL", "PHYSICAL"]),
                    privileges_required=random.choice(["NONE", "LOW", "HIGH"]),
                    raw_data={"generated": True},
                    asset_id=asset.id,
                    created_at=datetime.utcnow() - timedelta(days=random.randint(0, 365))
                )
                db.add(vuln)
                db.flush()

                # Add threat intel
                n_threats = random.randint(0, 3)
                for _ in range(n_threats):
                    threat = ThreatIntelData(
                        vulnerability_id=vuln.id,
                        source=random.choice(["recorded_future", "virus_total", "shodan"]),
                        threat_type=random.choice(["exploit", "malware", "ransomware"]),
                        confidence_score=random.uniform(0.1, 1.0),
                        last_seen=datetime.utcnow() - timedelta(days=random.randint(0, 90))
                    )
                    db.add(threat)

                # Add mitigations
                mitigation = VulnerabilityMitigation(
                    vulnerability_id=vuln.id,
                    recommendation="Generated mitigation advice",
                    implementation_status=random.choice(["not_started", "in_progress", "completed"]),
                    effectiveness_score=random.uniform(0, 10)
                )
                db.add(mitigation)

        db.commit()
        print(f"Created {n_assets} assets with vulnerabilities for training")
        
    except Exception as e:
        print(f"Error creating training data: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == '__main__':
    create_training_data()