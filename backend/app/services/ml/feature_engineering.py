from dataclasses import dataclass
from typing import List, Dict, Any, Optional
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.impute import SimpleImputer

@dataclass
class FeatureSet:
    """Container for processed features"""
    X: pd.DataFrame
    y: Optional[pd.Series] = None
    feature_names: List[str] = None
    categorical_features: List[str] = None
    numerical_features: List[str] = None
    scalers: Dict[str, StandardScaler] = None
    encoders: Dict[str, LabelEncoder] = None

class FeatureEngineer:
    """Feature engineering for vulnerability risk assessment"""
    
    def __init__(self):
        self.numerical_features = [
            'severity', 'cvss_score', 'asset_risk_score',
            'threat_count', 'avg_threat_confidence', 'days_since_discovery'
        ]
        self.categorical_features = [
            'attack_vector', 'attack_complexity', 'privileges_required',
            'asset_type'
        ]
        self.scalers = {}
        self.encoders = {}
        self.imputers = {}

    def prepare_features(self, data: pd.DataFrame, fit: bool = True) -> FeatureSet:
        """Prepare features for model training or prediction"""
        df = data.copy()
        
        # Handle dates
        if 'created_at' in df.columns:
            df['days_since_discovery'] = (pd.Timestamp.now() - pd.to_datetime(df['created_at'])).dt.days

        # Handle missing values
        for feature in self.numerical_features:
            if feature not in df.columns:
                df[feature] = 0
            if fit:
                self.imputers[feature] = SimpleImputer(strategy='mean')
                df[feature] = self.imputers[feature].fit_transform(df[[feature]])
            else:
                df[feature] = self.imputers[feature].transform(df[[feature]])

        # Scale numerical features
        for feature in self.numerical_features:
            if fit:
                self.scalers[feature] = StandardScaler()
                df[feature] = self.scalers[feature].fit_transform(df[[feature]])
            else:
                df[feature] = self.scalers[feature].transform(df[[feature]])

        # Encode categorical features
        for feature in self.categorical_features:
            if feature not in df.columns:
                df[feature] = 'UNKNOWN'
            if fit:
                self.encoders[feature] = LabelEncoder()
                df[feature] = self.encoders[feature].fit_transform(df[feature].fillna('UNKNOWN'))
            else:
                # Handle unseen categories
                df[feature] = df[feature].map(lambda x: x if x in self.encoders[feature].classes_ else 'UNKNOWN')
                df[feature] = self.encoders[feature].transform(df[feature])

        # Extract target if present
        y = None
        if 'risk_score' in df.columns:
            y = df['risk_score']
            df = df.drop('risk_score', axis=1)

        feature_names = self.numerical_features + self.categorical_features
        
        return FeatureSet(
            X=df[feature_names],
            y=y,
            feature_names=feature_names,
            categorical_features=self.categorical_features,
            numerical_features=self.numerical_features,
            scalers=self.scalers,
            encoders=self.encoders
        )

    def extract_threat_features(self, threat_data: List[Dict]) -> Dict[str, float]:
        """Extract features from threat intelligence data"""
        if not threat_data:
            return {
                'threat_count': 0,
                'avg_threat_confidence': 0,
                'max_threat_confidence': 0,
                'unique_threat_types': 0
            }

        threat_types = set()
        confidences = []
        
        for threat in threat_data:
            if 'threat_type' in threat:
                threat_types.add(threat['threat_type'])
            if 'confidence_score' in threat:
                confidences.append(threat['confidence_score'])

        return {
            'threat_count': len(threat_data),
            'avg_threat_confidence': np.mean(confidences) if confidences else 0,
            'max_threat_confidence': max(confidences) if confidences else 0,
            'unique_threat_types': len(threat_types)
        }