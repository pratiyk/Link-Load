from typing import Dict, Any, List
import numpy as np
from datetime import datetime
from loguru import logger

class RiskAnalyzer:
    def __init__(self):
        # Risk scoring weights
        self.weights = {
            'cvss_base': 0.4,
            'attack_complexity': 0.1,
            'exploit_availability': 0.15,
            'business_impact': 0.2,
            'compliance_impact': 0.15
        }
        
        # Compliance frameworks
        self.compliance_frameworks = {
            'pci_dss': {
                'weight': 0.3,
                'requirements': self._load_pci_requirements()
            },
            'owasp_top_10': {
                'weight': 0.4,
                'requirements': self._load_owasp_requirements()
            },
            'iso_27001': {
                'weight': 0.3,
                'requirements': self._load_iso_requirements()
            }
        }
    
    def _load_pci_requirements(self) -> Dict[str, Any]:
        """Load PCI DSS requirements mapping"""
        return {
            'injection': {'requirement': '6.5.1', 'weight': 0.2},
            'auth': {'requirement': '8.2', 'weight': 0.2},
            'crypto': {'requirement': '4.1', 'weight': 0.15},
            'data_protection': {'requirement': '3.4', 'weight': 0.25},
            'access_control': {'requirement': '7.1', 'weight': 0.2}
        }
    
    def _load_owasp_requirements(self) -> Dict[str, Any]:
        """Load OWASP Top 10 requirements mapping"""
        return {
            'injection': {'category': 'A1', 'weight': 0.2},
            'auth': {'category': 'A2', 'weight': 0.15},
            'sensitive_data': {'category': 'A3', 'weight': 0.15},
            'xxe': {'category': 'A4', 'weight': 0.1},
            'access_control': {'category': 'A5', 'weight': 0.15},
            'security_misconfig': {'category': 'A6', 'weight': 0.1},
            'xss': {'category': 'A7', 'weight': 0.15}
        }
    
    def _load_iso_requirements(self) -> Dict[str, Any]:
        """Load ISO 27001 requirements mapping"""
        return {
            'access_control': {'control': 'A.9', 'weight': 0.2},
            'crypto': {'control': 'A.10', 'weight': 0.15},
            'security': {'control': 'A.12', 'weight': 0.2},
            'compliance': {'control': 'A.18', 'weight': 0.15},
            'data_security': {'control': 'A.8', 'weight': 0.3}
        }
    
    async def analyze_risk(
        self, 
        finding: Dict[str, Any],
        business_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Analyze risk based on vulnerability finding and business context"""
        try:
            # Calculate base risk score
            base_risk = self._calculate_base_risk(finding)
            
            # Calculate business impact
            business_impact = self._calculate_business_impact(
                finding, 
                business_context
            )
            
            # Calculate compliance impact
            compliance_impact = self._calculate_compliance_impact(finding)
            
            # Calculate final risk score
            risk_score = (
                self.weights['cvss_base'] * base_risk +
                self.weights['business_impact'] * business_impact +
                self.weights['compliance_impact'] * compliance_impact
            )
            
            # Generate risk report
            report = {
                'risk_score': round(float(risk_score), 2),
                'risk_level': self._get_risk_level(risk_score),
                'business_impact': {
                    'score': round(float(business_impact), 2),
                    'factors': self._get_business_impact_factors(finding, business_context)
                },
                'compliance_impact': {
                    'score': round(float(compliance_impact), 2),
                    'frameworks': self._get_affected_frameworks(finding)
                },
                'remediation_priority': self._calculate_remediation_priority(
                    risk_score,
                    business_impact,
                    finding
                ),
                'timestamp': datetime.utcnow().isoformat()
            }
            
            return report
            
        except Exception as e:
            logger.error(f"Error analyzing risk: {str(e)}")
            return {
                'risk_score': 0.0,
                'risk_level': 'unknown',
                'business_impact': {'score': 0.0, 'factors': []},
                'compliance_impact': {'score': 0.0, 'frameworks': []},
                'remediation_priority': 'low',
                'timestamp': datetime.utcnow().isoformat()
            }
    
    def _calculate_base_risk(self, finding: Dict[str, Any]) -> float:
        """Calculate base risk score from CVSS and complexity"""
        try:
            cvss_score = float(finding.get('cvss_score', 0))
            if not 0 <= cvss_score <= 10:
                logger.warning(f"Invalid CVSS score: {cvss_score}, clamping to 0-10 range")
                cvss_score = max(0, min(cvss_score, 10))
        except (ValueError, TypeError):
            logger.error(f"Invalid CVSS score format: {finding.get('cvss_score')}, using 0")
            cvss_score = 0
            
        attack_complexity = self._get_attack_complexity_score(finding)
        exploit_availability = 1.0 if finding.get('exploit_available') else 0.0
        
        return (
            cvss_score / 10.0 * self.weights['cvss_base'] +
            attack_complexity * self.weights['attack_complexity'] +
            exploit_availability * self.weights['exploit_availability']
        )
    
    def _get_attack_complexity_score(self, finding: Dict[str, Any]) -> float:
        """Convert attack complexity to numeric score"""
        complexity_map = {
            'low': 1.0,
            'medium': 0.6,
            'high': 0.3
        }
        return complexity_map.get(
            finding.get('attack_complexity', 'medium').lower(), 
            0.6
        )
    
    def _calculate_business_impact(
        self,
        finding: Dict[str, Any],
        business_context: Dict[str, Any]
    ) -> float:
        """Calculate business impact score"""
        impact_score = 0.0
        
        # Asset criticality
        criticality_map = {
            'critical': 1.0,
            'high': 0.8,
            'medium': 0.5,
            'low': 0.2
        }
        impact_score += criticality_map.get(
            business_context.get('asset_criticality', 'medium').lower(),
            0.5
        )
        
        # Data sensitivity
        if business_context.get('sensitive_data', False):
            impact_score += 0.3
            
        # Customer impact
        if business_context.get('customer_facing', False):
            impact_score += 0.2
            
        # Revenue impact
        if business_context.get('revenue_impact', False):
            impact_score += 0.3
            
        return min(impact_score, 1.0)
    
    def _calculate_compliance_impact(self, finding: Dict[str, Any]) -> float:
        """Calculate compliance impact score"""
        impact_score = 0.0
        
        for framework, data in self.compliance_frameworks.items():
            framework_score = 0.0
            
            # Check each requirement in the framework
            for req_type, req_data in data['requirements'].items():
                if self._matches_requirement(finding, req_type):
                    framework_score += req_data['weight']
            
            impact_score += framework_score * data['weight']
            
        return min(impact_score, 1.0)
    
    def _matches_requirement(self, finding: Dict[str, Any], req_type: str) -> bool:
        """Check if finding matches a compliance requirement type"""
        # Convert finding attributes to lowercase for matching
        title = finding.get('title', '').lower()
        description = finding.get('description', '').lower()
        
        # Define keywords for each requirement type
        requirement_keywords = {
            'injection': ['sql injection', 'command injection', 'code injection'],
            'auth': ['authentication', 'authorization', 'credentials'],
            'crypto': ['encryption', 'cryptographic', 'ssl', 'tls'],
            'data_protection': ['data exposure', 'information disclosure', 'data leak'],
            'access_control': ['permission', 'privilege', 'access control'],
            'xxe': ['xxe', 'xml injection', 'xml external'],
            'security_misconfig': ['misconfiguration', 'default configuration'],
            'xss': ['xss', 'cross-site scripting']
        }
        
        # Check if any keywords match
        keywords = requirement_keywords.get(req_type, [])
        return any(kw in title or kw in description for kw in keywords)
    
    def _get_risk_level(self, risk_score: float) -> str:
        """Convert risk score to risk level"""
        try:
            score = float(risk_score)
            if not 0 <= score <= 1:
                logger.warning(f"Risk score {score} out of range, clamping to 0-1")
                score = max(0, min(score, 1))
        except (ValueError, TypeError):
            logger.error(f"Invalid risk score: {risk_score}, defaulting to 0")
            score = 0
            
        if score >= 0.8:
            return 'critical'
        elif score >= 0.6:
            return 'high'
        elif score >= 0.4:
            return 'medium'
        elif score >= 0.2:
            return 'low'
        else:
            return 'info'
    
    def _get_business_impact_factors(
        self,
        finding: Dict[str, Any],
        business_context: Dict[str, Any]
    ) -> List[str]:
        """Get list of business impact factors"""
        factors = []
        
        if business_context.get('sensitive_data'):
            factors.append('Sensitive Data Exposure')
        if business_context.get('customer_facing'):
            factors.append('Customer-Facing System')
        if business_context.get('revenue_impact'):
            factors.append('Direct Revenue Impact')
        if business_context.get('compliance_required'):
            factors.append('Compliance Requirements')
            
        return factors
    
    def _get_affected_frameworks(self, finding: Dict[str, Any]) -> List[str]:
        """Get list of affected compliance frameworks"""
        frameworks = []
        
        for framework, data in self.compliance_frameworks.items():
            for req_type in data['requirements'].keys():
                if self._matches_requirement(finding, req_type):
                    frameworks.append(framework.upper())
                    break
                    
        return list(set(frameworks))
    
    def _calculate_remediation_priority(
        self,
        risk_score: float,
        business_impact: float,
        finding: Dict[str, Any]
    ) -> str:
        """Calculate remediation priority"""
        # Base priority on risk score and business impact
        priority_score = (risk_score * 0.7) + (business_impact * 0.3)
        
        # Adjust for exploit availability
        if finding.get('exploit_available'):
            priority_score = min(priority_score + 0.2, 1.0)
        
        # Convert to priority level
        if priority_score >= 0.8:
            return 'critical'
        elif priority_score >= 0.6:
            return 'high'
        elif priority_score >= 0.4:
            return 'medium'
        else:
            return 'low'

# Global analyzer instance
risk_analyzer = RiskAnalyzer()