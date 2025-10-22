"""Feature engineering for vulnerability risk scoring."""
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.impute import KNNImputer
from sklearn.feature_selection import RFE
from xgboost import XGBRegressor

class FeatureEngineer:
    """Feature engineering for vulnerability risk assessment."""

    def __init__(self):
        self.scaler = StandardScaler()
        self.imputer = KNNImputer(n_neighbors=5)
        self.feature_selector = None
        self.selected_features = None

    def extract_base_features(self, vulnerability: Dict[str, Any]) -> Dict[str, float]:
        """Extract base features from vulnerability data."""
        features = {
            # Core severity features
            'cvss_score': float(vulnerability.get('cvss_score', 0)),
            'cvss_temporal': float(vulnerability.get('cvss_temporal_score', 0)),
            'cvss_environmental': float(vulnerability.get('cvss_environmental_score', 0)),
            
            # Attack complexity features
            'attack_complexity': self._normalize_complexity(vulnerability.get('attack_complexity', 'high')),
            'privileges_required': self._normalize_privileges(vulnerability.get('privileges_required', 'high')),
            'user_interaction': 1.0 if vulnerability.get('user_interaction', 'required') == 'none' else 0.5,
            
            # Impact features
            'confidentiality_impact': self._normalize_impact(vulnerability.get('confidentiality_impact', 'none')),
            'integrity_impact': self._normalize_impact(vulnerability.get('integrity_impact', 'none')),
            'availability_impact': self._normalize_impact(vulnerability.get('availability_impact', 'none')),
            
            # Exploit features
            'exploit_code_maturity': self._normalize_maturity(vulnerability.get('exploit_code_maturity', 'unproven')),
            'exploit_count': float(vulnerability.get('exploit_count', 0)),
            'exploitability_score': float(vulnerability.get('exploitability_score', 0)),
            
            # Temporal features
            'age_days': self._calculate_age(vulnerability.get('published_date')),
            'patch_available': 1.0 if vulnerability.get('patch_available', False) else 0.0,
            'patch_age_days': self._calculate_patch_age(vulnerability),
            
            # Asset features
            'asset_criticality': self._normalize_criticality(vulnerability.get('asset_criticality', 'low')),
            'exposed_to_internet': 1.0 if vulnerability.get('exposed_to_internet', False) else 0.0,
            'affected_systems': float(vulnerability.get('affected_systems_count', 0)),
            
            # Threat intelligence features
            'threat_sources': float(vulnerability.get('threat_sources_count', 0)),
            'threat_score': float(vulnerability.get('threat_score', 0)),
            'malicious_sources': float(vulnerability.get('malicious_sources_count', 0)),
        }
        
        # Add threat recency features
        threat_dates = vulnerability.get('threat_dates', [])
        if threat_dates:
            features['latest_threat_age'] = self._calculate_latest_threat_age(threat_dates)
            features['threat_frequency_30d'] = self._calculate_threat_frequency(threat_dates, days=30)
        else:
            features['latest_threat_age'] = 365.0  # Default to 1 year if no threats
            features['threat_frequency_30d'] = 0.0
        
        return features

    def _normalize_complexity(self, complexity: str) -> float:
        """Normalize attack complexity values."""
        mapping = {'low': 1.0, 'medium': 0.66, 'high': 0.33}
        return mapping.get(complexity.lower(), 0.5)

    def _normalize_privileges(self, privileges: str) -> float:
        """Normalize required privileges values."""
        mapping = {'none': 1.0, 'low': 0.75, 'medium': 0.5, 'high': 0.25}
        return mapping.get(privileges.lower(), 0.5)

    def _normalize_impact(self, impact: str) -> float:
        """Normalize impact values."""
        mapping = {'high': 1.0, 'medium': 0.66, 'low': 0.33, 'none': 0.0}
        return mapping.get(impact.lower(), 0.0)

    def _normalize_maturity(self, maturity: str) -> float:
        """Normalize exploit code maturity values."""
        mapping = {
            'high': 1.0,
            'functional': 0.75,
            'proof-of-concept': 0.5,
            'unproven': 0.25,
            'not-defined': 0.0
        }
        return mapping.get(maturity.lower(), 0.0)

    def _normalize_criticality(self, criticality: str) -> float:
        """Normalize asset criticality values."""
        mapping = {'critical': 1.0, 'high': 0.75, 'medium': 0.5, 'low': 0.25}
        return mapping.get(criticality.lower(), 0.25)

    def _calculate_age(self, published_date: Optional[str]) -> float:
        """Calculate vulnerability age in days."""
        if not published_date:
            return 0.0
        try:
            pub_date = datetime.fromisoformat(published_date.replace('Z', '+00:00'))
            age = (datetime.now(pub_date.tzinfo) - pub_date).days
            return float(max(0, age))
        except (ValueError, TypeError):
            return 0.0

    def _calculate_patch_age(self, vulnerability: Dict[str, Any]) -> float:
        """Calculate the age of the patch in days."""
        patch_date = vulnerability.get('patch_published_date')
        if not patch_date:
            return 0.0
        try:
            patch_dt = datetime.fromisoformat(patch_date.replace('Z', '+00:00'))
            age = (datetime.now(patch_dt.tzinfo) - patch_dt).days
            return float(max(0, age))
        except (ValueError, TypeError):
            return 0.0

    def _calculate_latest_threat_age(self, threat_dates: List[str]) -> float:
        """Calculate days since the most recent threat."""
        if not threat_dates:
            return 365.0  # Default to 1 year if no threats
        try:
            dates = [datetime.fromisoformat(d.replace('Z', '+00:00')) for d in threat_dates]
            latest = max(dates)
            age = (datetime.now(latest.tzinfo) - latest).days
            return float(max(0, age))
        except (ValueError, TypeError):
            return 365.0

    def _calculate_threat_frequency(self, threat_dates: List[str], days: int = 30) -> float:
        """Calculate threat frequency within specified days."""
        if not threat_dates:
            return 0.0
        try:
            dates = [datetime.fromisoformat(d.replace('Z', '+00:00')) for d in threat_dates]
            cutoff = datetime.now(dates[0].tzinfo) - timedelta(days=days)
            recent_threats = sum(1 for d in dates if d >= cutoff)
            return float(recent_threats)
        except (ValueError, TypeError):
            return 0.0

    def select_features(self, X: pd.DataFrame, y: pd.Series, n_features: int = 15) -> List[str]:
        """Select most important features using RFE."""
        model = XGBRegressor(n_estimators=100, learning_rate=0.1)
        selector = RFE(model, n_features_to_select=n_features, step=1)
        selector.fit(X, y)
        
        self.feature_selector = selector
        self.selected_features = [
            feature for feature, selected in zip(X.columns, selector.support_)
            if selected
        ]
        return self.selected_features

    def transform_features(self, features_dict: Dict[str, float]) -> np.ndarray:
        """Transform raw features into model input."""
        # Convert to DataFrame for easier handling
        df = pd.DataFrame([features_dict])
        
        # Fill missing values
        df = pd.DataFrame(self.imputer.fit_transform(df), columns=df.columns)
        
        # Scale features
        df = pd.DataFrame(self.scaler.fit_transform(df), columns=df.columns)
        
        # Select features if feature selection was performed
        if self.selected_features:
            df = df[self.selected_features]
        
        return df.values

    def get_feature_names(self) -> List[str]:
        """Get list of feature names in order."""
        return self.selected_features if self.selected_features else []