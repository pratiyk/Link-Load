import random
from datetime import datetime, timedelta
import pandas as pd
import numpy as np

def generate_synthetic_data(n_samples=1000):
    """Generate synthetic vulnerability data for ML training"""
    
    # Define possible values for categorical features
    attack_vectors = ['NETWORK', 'ADJACENT', 'LOCAL', 'PHYSICAL']
    attack_complexities = ['LOW', 'HIGH']
    privileges_required = ['NONE', 'LOW', 'HIGH']
    asset_types = ['domain', 'ip', 'webapp', 'server', 'database']
    threat_types = ['exploit', 'malware', 'ransomware', 'botnet', 'apt']
    
    data = []
    for _ in range(n_samples):
        # Generate base vulnerability features
        base_severity = random.uniform(0, 10)
        cvss_base = random.uniform(max(0, base_severity-2), min(10, base_severity+2))
        
        # Generate threat intel features
        n_threats = random.randint(0, 5)
        threat_confidences = [random.uniform(0.1, 1.0) for _ in range(n_threats)]
        avg_threat_confidence = sum(threat_confidences) / len(threat_confidences) if threat_confidences else 0
        
        # Calculate synthetic risk score (target variable)
        # This is a simplified model of how risk might be calculated
        base_risk = (base_severity * 0.4 + cvss_base * 0.3) 
        threat_modifier = avg_threat_confidence * n_threats * 0.1
        asset_criticality = random.uniform(0, 10)
        asset_modifier = asset_criticality * 0.2
        
        risk_score = min(10, base_risk + threat_modifier + asset_modifier)
        
        record = {
            'severity': base_severity,
            'cvss_score': cvss_base,
            'attack_vector': random.choice(attack_vectors),
            'attack_complexity': random.choice(attack_complexities),
            'privileges_required': random.choice(privileges_required),
            'asset_type': random.choice(asset_types),
            'asset_risk_score': asset_criticality,
            'threat_count': n_threats,
            'avg_threat_confidence': avg_threat_confidence,
            'threat_types': random.sample(threat_types, random.randint(0, min(3, len(threat_types)))),
            'days_since_discovery': random.randint(0, 365),
            'risk_score': risk_score  # Target variable
        }
        data.append(record)
    
    df = pd.DataFrame(data)
    df.to_csv('synthetic_training_data.csv', index=False)
    print(f"Generated {n_samples} synthetic records in synthetic_training_data.csv")
    
    # Generate some analytics
    print("\nData Statistics:")
    print(df.describe())
    
    # Show correlation with risk score for numerical features
    print("\nCorrelation with risk_score:")
    numerical_cols = ['severity', 'cvss_score', 'threat_count', 'avg_threat_confidence', 'days_since_discovery', 'risk_score']
    correlations = df[numerical_cols].corr()['risk_score'].sort_values(ascending=False)
    print(correlations)

    # Print categorical feature distributions
    print("\nCategorical Feature Distributions:")
    categorical_cols = ['attack_vector', 'attack_complexity', 'privileges_required', 'asset_type']
    for col in categorical_cols:
        print(f"\n{col} distribution:")
        print(df[col].value_counts())

if __name__ == '__main__':
    generate_synthetic_data()