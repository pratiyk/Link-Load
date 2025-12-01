from typing import List, Dict, Any, Optional
from app.core.config import settings
import pandas as pd
import joblib
import os
from loguru import logger

# Optional ML dependencies
try:
    import torch
    TORCH_AVAILABLE = True
except ImportError:
    torch = None  # type: ignore
    TORCH_AVAILABLE = False

try:
    from transformers import pipeline
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    pipeline = None  # type: ignore
    TRANSFORMERS_AVAILABLE = False

try:
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    StandardScaler = None  # type: ignore
    SKLEARN_AVAILABLE = False


class VulnerabilityAnalyzer:
    def __init__(self):
        self.llm_analyzer = None
        self.risk_model = None
        self.severity_model = None
        self.scaler = None
        self._initialized = False
        
        # Only initialize if all dependencies are available
        if TRANSFORMERS_AVAILABLE and TORCH_AVAILABLE:
            try:
                device = 0 if torch.cuda.is_available() else -1
                self.llm_analyzer = pipeline(
                    "text-classification",
                    model="microsoft/codebert-base-mlm",
                    device=device
                )
            except Exception as e:
                logger.warning(f"Could not initialize LLM analyzer: {e}")
        
        # Load ML models if available
        models_path = "ml_models/vulnerability_analysis"
        if os.path.exists(models_path):
            try:
                self.risk_model = joblib.load(os.path.join(models_path, "risk_model.joblib"))
                self.severity_model = joblib.load(os.path.join(models_path, "severity_model.joblib"))
                self.scaler = joblib.load(os.path.join(models_path, "scaler.joblib"))
                self._initialized = True
            except Exception as e:
                logger.warning(f"Could not load ML models: {e}")
        
    async def analyze_vulnerability(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze a vulnerability finding using ML models and LLM"""
        try:
            # Extract features
            features = self._extract_features(finding)
            
            # Get ML model predictions
            risk_score = self._predict_risk(features)
            severity = self._predict_severity(features)
            
            # Get LLM analysis
            llm_analysis = await self._get_llm_analysis(finding)
            
            return {
                "risk_score": float(risk_score),
                "severity": severity,
                "analysis": llm_analysis,
                "confidence": self._calculate_confidence(finding)
            }
            
        except Exception as e:
            logger.error(f"Error analyzing vulnerability: {str(e)}")
            return {
                "risk_score": 0.0,
                "severity": "unknown",
                "analysis": "Analysis failed",
                "confidence": 0.0
            }
    
    def _extract_features(self, finding: Dict[str, Any]) -> pd.DataFrame:
        """Extract numerical and categorical features from finding"""
        features = {
            "cvss_score": finding.get("cvss_score", 0.0),
            "affected_components": len(finding.get("affected_components", [])),
            "prerequisites": len(finding.get("prerequisites", [])),
            "has_poc": 1 if finding.get("proof_of_concept") else 0,
            "has_exploit": 1 if finding.get("exploit_available") else 0
        }
        return pd.DataFrame([features])
    
    def _predict_risk(self, features: pd.DataFrame) -> float:
        """Predict risk score using ML model"""
        if self.scaler is None or self.risk_model is None:
            return 0.5  # Default medium risk
        scaled_features = self.scaler.transform(features)
        return self.risk_model.predict_proba(scaled_features)[0][1]
    
    def _predict_severity(self, features: pd.DataFrame) -> str:
        """Predict severity level using ML model"""
        if self.severity_model is None:
            return "medium"  # Default severity
        severity_map = {
            0: "low",
            1: "medium",
            2: "high",
            3: "critical"
        }
        prediction = self.severity_model.predict(features)[0]
        return severity_map.get(prediction, "unknown")
    
    async def _get_llm_analysis(self, finding: Dict[str, Any]) -> str:
        """Get LLM-based analysis of the vulnerability"""
        if self.llm_analyzer is None:
            return "LLM analysis not available - transformers package not installed"
            
        try:
            context = f"""
            Vulnerability: {finding.get('title', 'Unknown')}
            Description: {finding.get('description', 'No description')}
            Affected Components: {', '.join(finding.get('affected_components', []))}
            Technical Details: {finding.get('technical_details', 'No details')}
            """
            
            result = self.llm_analyzer(context, max_length=512)
            return result[0]["sequence"]
            
        except Exception as e:
            logger.error(f"LLM analysis failed: {str(e)}")
            return "LLM analysis unavailable"
    
    def _calculate_confidence(self, finding: Dict[str, Any]) -> float:
        """Calculate confidence score for the analysis"""
        confidence = 0.0
        
        # Add confidence based on available data
        if finding.get("cvss_score"):
            confidence += 0.3
        if finding.get("technical_details"):
            confidence += 0.2
        if finding.get("proof_of_concept"):
            confidence += 0.3
        if finding.get("affected_components"):
            confidence += 0.2
            
        return min(confidence, 1.0)

# Global analyzer instance - lazy initialization
_analyzer: Optional[VulnerabilityAnalyzer] = None

def get_analyzer() -> VulnerabilityAnalyzer:
    global _analyzer
    if _analyzer is None:
        _analyzer = VulnerabilityAnalyzer()
    return _analyzer

# For backwards compatibility
analyzer = None  # Will be initialized on first use