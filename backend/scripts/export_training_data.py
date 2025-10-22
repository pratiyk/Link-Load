from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import pandas as pd
from app.database import get_db
from app.models.vulnerability_models import VulnerabilityData, ThreatIntelData
from app.models.asset_models import DiscoveredAsset

def export_training_data():
    """Export vulnerability and related data for ML training"""
    db = next(get_db())
    
    # Query vulnerabilities with related data
    vulnerabilities = db.query(VulnerabilityData).all()
    
    training_data = []
    for vuln in vulnerabilities:
        # Basic vulnerability features
        record = {
            'vulnerability_id': vuln.id,
            'severity': vuln.severity,
            'cvss_score': vuln.cvss_score,
            'attack_complexity': vuln.attack_complexity,
            'attack_vector': vuln.attack_vector,
            'privileges_required': vuln.privileges_required,
            
            # Asset features
            'asset_type': vuln.asset.asset_type if vuln.asset else None,
            'asset_risk_score': vuln.asset.risk_score if vuln.asset else None,
            
            # Threat intel features
            'threat_count': len(vuln.intel_data),
            'avg_threat_confidence': sum(t.confidence_score for t in vuln.intel_data) / len(vuln.intel_data) if vuln.intel_data else 0,
            'latest_threat_seen': max(t.last_seen for t in vuln.intel_data) if vuln.intel_data else None,
            
            # Target variable (if available)
            'actual_risk_score': vuln.risk_score if hasattr(vuln, 'risk_score') else None
        }
        training_data.append(record)
    
    # Convert to DataFrame and save
    df = pd.DataFrame(training_data)
    df.to_csv('training_data.csv', index=False)
    print(f"Exported {len(df)} records to training_data.csv")

if __name__ == '__main__':
    export_training_data()