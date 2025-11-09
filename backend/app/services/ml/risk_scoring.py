"""Machine learning service for risk scoring and MITRE ATT&CK mapping."""
import os
from typing import Dict, Any, List, Optional

from .pipeline.ml_pipeline import MLPipeline
from app.utils.datetime_utils import utc_now

class RiskScoringEngine:
    """Advanced risk scoring engine using ML models."""
    
    def __init__(self):
        """Initialize the risk scoring engine with ML pipeline."""
        self.pipeline = MLPipeline(
            model_dir=os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                "ml_models",
                "risk_scoring"
            )
        )
        try:
            self.pipeline.load_latest_model()
        except RuntimeError:
            # No model available yet, will use fallback scoring
            pass

    def calculate_risk_score(self, vulnerability: Any) -> Dict[str, Any]:
        """Calculate risk score using ML models or fallback to basic scoring."""
        try:
            if self.pipeline.model is not None:
                prediction = self.pipeline.predict(vulnerability)
                return {
                    "score": prediction["risk_score"],
                    "confidence": prediction["confidence"],
                    "feature_importance": prediction["feature_importance"],
                    "uncertainty": prediction["uncertainty"],
                    "calculated_at": prediction["prediction_time"]
                }
        except Exception as e:
            # Log error and fall back to basic scoring
            print(f"ML prediction failed: {e}")
        
        # Fallback to basic scoring if ML fails
        return {
            "score": 5.0,  # Default medium risk
            "confidence": 0.5,
            "calculated_at": utc_now().isoformat(),
            "note": "Using fallback scoring due to ML unavailability"
        }
        
    def map_to_mitre_techniques(
        self, 
        description: str,
        threshold: float = 0.7
    ) -> List[Dict[str, Any]]:
        """Map vulnerability description to MITRE ATT&CK techniques."""
        # TODO: Implement ML-based MITRE mapping
        return []
        
    def analyze_vulnerability(self, vulnerability: Any) -> Dict[str, Any]:
        """Perform comprehensive vulnerability analysis using ML."""
        risk_analysis = self.calculate_risk_score(vulnerability)
        mitre_mapping = self.map_to_mitre_techniques(str(vulnerability))
        
        # Get model performance metrics if available
        performance_metrics = {}
        if self.pipeline.model is not None:
            performance_metrics = self.pipeline.monitor_performance()
        
        # Check for model drift if we have recent data
        drift_info = {}
        if hasattr(vulnerability, 'recent_predictions'):
            drift_info = self.pipeline.check_model_drift(
                vulnerability.recent_predictions
            )
        
        return {
            "risk_analysis": risk_analysis,
            "mitre_mapping": mitre_mapping,
            "model_performance": performance_metrics,
            "model_drift": drift_info,
            "threat_summary": self._generate_threat_summary(vulnerability),
            "recommendations": self._generate_recommendations(
                vulnerability,
                risk_analysis,
                mitre_mapping
            )
        }
    
    def _generate_threat_summary(self, vulnerability: Any) -> Dict[str, Any]:
        """Generate threat summary with available data."""
        return {
            "total_threats": len(getattr(vulnerability, 'threat_data', [])),
            "avg_severity": self._calculate_avg_severity(vulnerability),
            "avg_confidence": self._calculate_avg_confidence(vulnerability),
            "threat_types": self._extract_threat_types(vulnerability)
        }
    
    def _calculate_avg_severity(self, vulnerability: Any) -> float:
        """Calculate average severity from threat data."""
        threat_data = getattr(vulnerability, 'threat_data', [])
        if not threat_data:
            return 0.0
        severities = [t.get('severity', 0.0) for t in threat_data]
        return sum(severities) / len(severities) if severities else 0.0
    
    def _calculate_avg_confidence(self, vulnerability: Any) -> float:
        """Calculate average confidence from threat data."""
        threat_data = getattr(vulnerability, 'threat_data', [])
        if not threat_data:
            return 0.0
        confidence_scores = [t.get('confidence', 0.0) for t in threat_data]
        return sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0.0
    
    def _extract_threat_types(self, vulnerability: Any) -> List[str]:
        """Extract unique threat types from threat data."""
        threat_data = getattr(vulnerability, 'threat_data', [])
        return list(set(t.get('type', '') for t in threat_data if t.get('type')))
    
    def _generate_recommendations(
        self,
        vulnerability: Any,
        risk_analysis: Dict[str, Any],
        mitre_mapping: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Generate prioritized security recommendations."""
        recommendations = []
        
        # High-risk recommendations
        if risk_analysis.get("score", 0) > 7.5:
            recommendations.append({
                "priority": "critical",
                "action": "Immediate patching required",
                "details": "Critical vulnerability with high risk score"
            })
            
        # Risk-based recommendations
        if risk_analysis.get("score", 0) > 5.0:
            recommendations.append({
                "priority": "high",
                "action": "Implement security controls",
                "details": "High-risk vulnerability requiring attention"
            })
            
        # Add basic security recommendations
        recommendations.extend([
            {
                "priority": "medium",
                "action": "Update security configurations",
                "details": "Ensure all security settings are properly configured"
            },
            {
                "priority": "medium",
                "action": "Implement access controls",
                "details": "Review and strengthen access control measures"
            },
            {
                "priority": "medium",
                "action": "Regular security audits",
                "details": "Conduct periodic security assessments"
            }
        ])
        
        return recommendations

# Initialize global risk scoring engine
risk_engine = RiskScoringEngine()