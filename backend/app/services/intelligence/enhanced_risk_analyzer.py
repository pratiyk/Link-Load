"""
Enhanced Risk Analyzer with Business Context and Prioritization.
Provides comprehensive risk scoring, business impact analysis, and remediation prioritization.
"""
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from enum import Enum

from app.utils.datetime_utils import utc_now

logger = logging.getLogger(__name__)


class RiskLevel(str, Enum):
    """Risk level categories."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class RemediationPriority(str, Enum):
    """Remediation priority levels."""
    P0_IMMEDIATE = "P0 - Immediate (0-24h)"
    P1_URGENT = "P1 - Urgent (1-3 days)"
    P2_HIGH = "P2 - High (1 week)"
    P3_MEDIUM = "P3 - Medium (2 weeks)"
    P4_LOW = "P4 - Low (1 month)"


class IndustryType(str, Enum):
    """Industry types for risk templates."""
    FINANCIAL = "financial"
    HEALTHCARE = "healthcare"
    ECOMMERCE = "ecommerce"
    GOVERNMENT = "government"
    TECHNOLOGY = "technology"
    EDUCATION = "education"
    GENERAL = "general"


class EnhancedRiskAnalyzer:
    """
    Enhanced risk analyzer with business context integration,
    industry-specific risk templates, and cost-benefit analysis.
    """

    def __init__(self):
        """Initialize risk analyzer with weights and frameworks."""
        # Enhanced risk scoring weights
        self.weights = {
            'cvss_base': 0.30,
            'attack_complexity': 0.10,
            'exploit_availability': 0.15,
            'business_impact': 0.25,
            'compliance_impact': 0.10,
            'asset_criticality': 0.10
        }

        # Compliance frameworks with updated weights
        self.compliance_frameworks = {
            'pci_dss': {
                'weight': 0.30,
                'requirements': self._load_pci_requirements()
            },
            'owasp_top_10': {
                'weight': 0.25,
                'requirements': self._load_owasp_requirements()
            },
            'iso_27001': {
                'weight': 0.20,
                'requirements': self._load_iso_requirements()
            },
            'gdpr': {
                'weight': 0.15,
                'requirements': self._load_gdpr_requirements()
            },
            'hipaa': {
                'weight': 0.10,
                'requirements': self._load_hipaa_requirements()
            }
        }

        # Industry-specific risk multipliers
        self.industry_risk_multipliers = {
            IndustryType.FINANCIAL: {
                'data_breach': 2.0,
                'authentication': 1.8,
                'encryption': 1.7,
                'access_control': 1.6
            },
            IndustryType.HEALTHCARE: {
                'data_breach': 2.2,
                'phi_exposure': 2.0,
                'encryption': 1.8,
                'audit_logging': 1.5
            },
            IndustryType.ECOMMERCE: {
                'payment_security': 2.0,
                'session_management': 1.7,
                'injection': 1.6,
                'xss': 1.5
            },
            IndustryType.GOVERNMENT: {
                'data_breach': 1.9,
                'access_control': 1.8,
                'encryption': 1.7,
                'audit_logging': 1.6
            },
            IndustryType.TECHNOLOGY: {
                'code_execution': 1.8,
                'api_security': 1.6,
                'supply_chain': 1.5,
                'secrets_exposure': 1.7
            },
            IndustryType.EDUCATION: {
                'data_breach': 1.5,
                'privacy': 1.4,
                'access_control': 1.3,
                'authentication': 1.3
            },
            IndustryType.GENERAL: {
                'default': 1.0
            }
        }

    def _load_pci_requirements(self) -> Dict[str, Any]:
        """Load PCI DSS requirements mapping."""
        return {
            'injection': {'requirement': '6.5.1', 'weight': 0.25, 'penalty': 'high'},
            'authentication': {'requirement': '8.1-8.3', 'weight': 0.20, 'penalty': 'critical'},
            'encryption': {'requirement': '3.4', 'weight': 0.20, 'penalty': 'critical'},
            'access_control': {'requirement': '7.1', 'weight': 0.15, 'penalty': 'high'},
            'logging': {'requirement': '10.1', 'weight': 0.10, 'penalty': 'medium'},
            'network_security': {'requirement': '1.1', 'weight': 0.10, 'penalty': 'high'}
        }

    def _load_owasp_requirements(self) -> Dict[str, Any]:
        """Load OWASP Top 10 requirements mapping."""
        return {
            'broken_access_control': {'category': 'A01:2021', 'weight': 0.20, 'severity_multiplier': 1.8},
            'cryptographic_failures': {'category': 'A02:2021', 'weight': 0.18, 'severity_multiplier': 1.7},
            'injection': {'category': 'A03:2021', 'weight': 0.16, 'severity_multiplier': 1.9},
            'insecure_design': {'category': 'A04:2021', 'weight': 0.14, 'severity_multiplier': 1.5},
            'security_misconfiguration': {'category': 'A05:2021', 'weight': 0.12, 'severity_multiplier': 1.4},
            'vulnerable_components': {'category': 'A06:2021', 'weight': 0.10, 'severity_multiplier': 1.6},
            'identification_auth_failures': {'category': 'A07:2021', 'weight': 0.10, 'severity_multiplier': 1.7}
        }

    def _load_iso_requirements(self) -> Dict[str, Any]:
        """Load ISO 27001 requirements mapping."""
        return {
            'access_control': {'control': 'A.9', 'weight': 0.25},
            'cryptography': {'control': 'A.10', 'weight': 0.20},
            'operations_security': {'control': 'A.12', 'weight': 0.20},
            'communications_security': {'control': 'A.13', 'weight': 0.15},
            'system_acquisition': {'control': 'A.14', 'weight': 0.20}
        }

    def _load_gdpr_requirements(self) -> Dict[str, Any]:
        """Load GDPR requirements mapping."""
        return {
            'data_protection': {'article': '32', 'weight': 0.35, 'fine_multiplier': 2.0},
            'breach_notification': {'article': '33-34', 'weight': 0.25, 'fine_multiplier': 1.8},
            'data_minimization': {'article': '5', 'weight': 0.20, 'fine_multiplier': 1.5},
            'consent': {'article': '7', 'weight': 0.20, 'fine_multiplier': 1.6}
        }

    def _load_hipaa_requirements(self) -> Dict[str, Any]:
        """Load HIPAA requirements mapping."""
        return {
            'phi_protection': {'rule': 'Privacy Rule', 'weight': 0.35, 'penalty': 'critical'},
            'encryption': {'rule': 'Security Rule §164.312', 'weight': 0.25, 'penalty': 'critical'},
            'access_control': {'rule': 'Security Rule §164.308', 'weight': 0.20, 'penalty': 'high'},
            'audit_controls': {'rule': 'Security Rule §164.312', 'weight': 0.20, 'penalty': 'high'}
        }

    async def analyze_comprehensive_risk(
        self,
        vulnerability: Dict[str, Any],
        business_context: Dict[str, Any],
        mitre_techniques: List[Dict[str, Any]],
        threat_intel: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Perform comprehensive risk analysis with business context.

        Args:
            vulnerability: Vulnerability data
            business_context: Business context including industry, asset criticality, etc.
            mitre_techniques: Mapped MITRE ATT&CK techniques
            threat_intel: Real-time threat intelligence data

        Returns:
            Comprehensive risk analysis with scores, priorities, and recommendations
        """
        try:
            # Calculate base risk components
            base_risk = self._calculate_base_risk(vulnerability)
            attack_complexity = self._get_attack_complexity_score(vulnerability)
            exploit_score = self._assess_exploit_availability(vulnerability, threat_intel)

            # Business context analysis
            business_impact = await self._calculate_business_impact(
                vulnerability,
                business_context,
                mitre_techniques
            )

            # Compliance impact with multiple frameworks
            compliance_impact = self._calculate_comprehensive_compliance_impact(
                vulnerability,
                business_context
            )

            # Asset criticality
            asset_score = self._get_asset_criticality_score(business_context)

            # Industry-specific risk adjustment
            industry_multiplier = self._get_industry_risk_multiplier(
                vulnerability,
                business_context.get('industry', IndustryType.GENERAL)
            )

            # Calculate weighted risk score
            risk_score = (
                self.weights['cvss_base'] * base_risk +
                self.weights['attack_complexity'] * attack_complexity +
                self.weights['exploit_availability'] * exploit_score +
                self.weights['business_impact'] * business_impact +
                self.weights['compliance_impact'] * compliance_impact['score'] +
                self.weights['asset_criticality'] * asset_score
            ) * industry_multiplier

            # Normalize to 0-10 scale
            risk_score = min(10.0, max(0.0, risk_score))

            # Determine risk level
            risk_level = self._get_risk_level(risk_score)

            # Calculate remediation priority with SLA
            remediation_priority = self._calculate_detailed_remediation_priority(
                risk_score,
                business_impact,
                exploit_score,
                compliance_impact,
                business_context
            )

            # Cost-benefit analysis
            cost_benefit = await self._perform_cost_benefit_analysis(
                vulnerability,
                business_context,
                risk_score
            )

            # Generate comprehensive recommendations
            recommendations = await self._generate_enhanced_recommendations(
                vulnerability,
                business_context,
                mitre_techniques,
                risk_score,
                compliance_impact
            )

            # Resource allocation suggestions
            resource_allocation = self._suggest_resource_allocation(
                risk_score,
                business_context,
                cost_benefit
            )

            return {
                'risk_score': round(risk_score, 2),
                'risk_level': risk_level.value,
                'remediation_priority': remediation_priority,
                'base_risk_score': round(base_risk, 2),
                'business_impact': {
                    'score': round(business_impact, 2),
                    'factors': self._get_business_impact_factors(vulnerability, business_context),
                    'monetary_risk': cost_benefit['potential_loss'],
                    'reputation_impact': self._assess_reputation_impact(business_context),
                    'operational_impact': self._assess_operational_impact(vulnerability, business_context)
                },
                'compliance_impact': compliance_impact,
                'exploit_analysis': {
                    'exploit_available': threat_intel.get('exploit_available', False) if threat_intel else False,
                    'exploit_maturity': threat_intel.get('exploit_maturity', 'unknown') if threat_intel else 'unknown',
                    'active_campaigns': threat_intel.get('active_campaigns', 0) if threat_intel else 0,
                    'score': round(exploit_score, 2)
                },
                'attack_surface': {
                    'complexity_score': round(attack_complexity, 2),
                    'attack_vectors': self._identify_attack_vectors(vulnerability),
                    'prerequisites': self._identify_attack_prerequisites(vulnerability)
                },
                'timeline': {
                    'sla_deadline': remediation_priority['sla_deadline'],
                    'recommended_fix_date': remediation_priority['recommended_fix_date'],
                    'grace_period_end': remediation_priority['grace_period_end']
                },
                'cost_benefit_analysis': cost_benefit,
                'recommendations': recommendations,
                'resource_allocation': resource_allocation,
                'industry_context': {
                    'industry': business_context.get('industry', IndustryType.GENERAL),
                    'risk_multiplier': round(industry_multiplier, 2),
                    'industry_specific_concerns': self._get_industry_concerns(
                        vulnerability,
                        business_context.get('industry', IndustryType.GENERAL)
                    )
                },
                'mitre_context': {
                    'techniques_count': len(mitre_techniques),
                    'tactics': list(set([t.get('tactic', 'Unknown') for t in mitre_techniques])),
                    'attack_patterns': [t.get('name', 'Unknown') for t in mitre_techniques[:3]]
                },
                'timestamp': utc_now().isoformat()
            }

        except Exception as e:
            logger.error(f"Comprehensive risk analysis failed: {e}")
            return {
                'risk_score': 0.0,
                'risk_level': RiskLevel.INFO.value,
                'error': str(e),
                'timestamp': utc_now().isoformat()
            }

    def _calculate_base_risk(self, vulnerability: Dict[str, Any]) -> float:
        """Calculate base risk score from CVSS and severity."""
        cvss_score = vulnerability.get('cvss_score', 0.0)
        if cvss_score:
            return min(1.0, cvss_score / 10.0)

        # Fallback to severity mapping
        severity_map = {
            'critical': 1.0,
            'high': 0.8,
            'medium': 0.5,
            'low': 0.2,
            'info': 0.0
        }
        severity = vulnerability.get('severity', 'info').lower()
        return severity_map.get(severity, 0.5)

    def _get_attack_complexity_score(self, vulnerability: Dict[str, Any]) -> float:
        """Convert attack complexity to numeric score (higher = easier to exploit)."""
        complexity = vulnerability.get('attack_complexity', 'high').lower()
        complexity_map = {
            'low': 0.9,    # Easy to exploit
            'medium': 0.6,
            'high': 0.3    # Difficult to exploit
        }
        return complexity_map.get(complexity, 0.5)

    def _assess_exploit_availability(
        self,
        vulnerability: Dict[str, Any],
        threat_intel: Optional[Dict[str, Any]]
    ) -> float:
        """Assess exploit availability and active exploitation."""
        if not threat_intel:
            return 0.5  # Default moderate score

        score = 0.0

        # Check exploit availability
        if threat_intel.get('exploit_available', False):
            score += 0.4

        # Exploit maturity
        maturity = threat_intel.get('exploit_maturity', 'proof_of_concept').lower()
        maturity_scores = {
            'weaponized': 0.3,
            'functional': 0.2,
            'proof_of_concept': 0.1,
            'unknown': 0.05
        }
        score += maturity_scores.get(maturity, 0.05)

        # Active campaigns
        active_campaigns = threat_intel.get('active_campaigns', 0)
        if active_campaigns > 0:
            score += min(0.3, active_campaigns * 0.1)

        return min(1.0, score)

    async def _calculate_business_impact(
        self,
        vulnerability: Dict[str, Any],
        business_context: Dict[str, Any],
        mitre_techniques: List[Dict[str, Any]]
    ) -> float:
        """Calculate comprehensive business impact score."""
        impact_score = 0.0

        # Asset criticality (0-0.3)
        criticality_map = {
            'critical': 0.30,
            'high': 0.25,
            'medium': 0.15,
            'low': 0.05
        }
        asset_criticality = business_context.get('asset_criticality', 'medium').lower()
        impact_score += criticality_map.get(asset_criticality, 0.15)

        # Data sensitivity (0-0.25)
        if business_context.get('sensitive_data', False):
            data_classification = business_context.get('data_classification', 'internal').lower()
            classification_scores = {
                'restricted': 0.25,
                'confidential': 0.20,
                'internal': 0.10,
                'public': 0.02
            }
            impact_score += classification_scores.get(data_classification, 0.10)

        # Customer-facing systems (0-0.20)
        if business_context.get('customer_facing', False):
            impact_score += 0.20

        # Revenue impact (0-0.25)
        if business_context.get('revenue_impact', False):
            revenue_criticality = business_context.get('revenue_criticality', 'medium').lower()
            revenue_scores = {'critical': 0.25, 'high': 0.20, 'medium': 0.10, 'low': 0.05}
            impact_score += revenue_scores.get(revenue_criticality, 0.10)

        # MITRE technique severity bonus
        if mitre_techniques:
            high_impact_tactics = ['Impact', 'Exfiltration', 'Command and Control']
            for technique in mitre_techniques:
                if technique.get('tactic') in high_impact_tactics:
                    impact_score += 0.05
                    break

        return min(1.0, impact_score)

    def _calculate_comprehensive_compliance_impact(
        self,
        vulnerability: Dict[str, Any],
        business_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Calculate impact across multiple compliance frameworks."""
        applicable_frameworks = business_context.get('compliance_frameworks', ['owasp_top_10'])
        
        framework_impacts = {}
        total_score = 0.0
        total_weight = 0.0

        for framework_name in applicable_frameworks:
            framework = self.compliance_frameworks.get(framework_name)
            if not framework:
                continue

            framework_score = 0.0
            matched_requirements = []

            for req_type, req_data in framework['requirements'].items():
                if self._matches_requirement(vulnerability, req_type):
                    framework_score += req_data.get('weight', 0.1)
                    matched_requirements.append({
                        'requirement': req_data.get('requirement') or req_data.get('category') or req_data.get('control'),
                        'type': req_type,
                        'severity': req_data.get('penalty', 'medium')
                    })

            framework_impacts[framework_name] = {
                'score': round(framework_score, 2),
                'weight': framework['weight'],
                'matched_requirements': matched_requirements
            }

            total_score += framework_score * framework['weight']
            total_weight += framework['weight']

        # Normalize score
        normalized_score = (total_score / total_weight) if total_weight > 0 else 0.0

        return {
            'score': round(min(1.0, normalized_score), 2),
            'frameworks': framework_impacts,
            'compliance_risk_level': self._get_compliance_risk_level(normalized_score),
            'regulatory_requirements': self._get_regulatory_requirements(vulnerability, business_context)
        }

    def _matches_requirement(self, vulnerability: Dict[str, Any], req_type: str) -> bool:
        """Check if vulnerability matches a compliance requirement type."""
        vuln_title = vulnerability.get('title', '').lower()
        vuln_desc = vulnerability.get('description', '').lower()
        combined_text = f"{vuln_title} {vuln_desc}"

        # Pattern matching for requirements
        patterns = {
            'injection': ['injection', 'sql', 'command', 'ldap', 'xpath'],
            'authentication': ['auth', 'password', 'credential', 'login', 'session'],
            'encryption': ['encrypt', 'crypto', 'tls', 'ssl', 'cipher'],
            'access_control': ['access', 'authorization', 'permission', 'privilege'],
            'logging': ['log', 'audit', 'monitor'],
            'xss': ['xss', 'cross-site scripting', 'script injection'],
            'broken_access_control': ['access control', 'idor', 'path traversal'],
            'cryptographic_failures': ['weak', 'encryption', 'hash', 'crypto'],
            'data_protection': ['data', 'pii', 'personal', 'privacy'],
            'phi_protection': ['phi', 'health', 'medical', 'patient']
        }

        req_patterns = patterns.get(req_type, [req_type])
        return any(pattern in combined_text for pattern in req_patterns)

    def _get_asset_criticality_score(self, business_context: Dict[str, Any]) -> float:
        """Get asset criticality score."""
        criticality = business_context.get('asset_criticality', 'medium').lower()
        scores = {'critical': 1.0, 'high': 0.75, 'medium': 0.5, 'low': 0.25}
        return scores.get(criticality, 0.5)

    def _get_industry_risk_multiplier(
        self,
        vulnerability: Dict[str, Any],
        industry: str
    ) -> float:
        """Get industry-specific risk multiplier."""
        industry_enum = IndustryType(industry) if industry in [i.value for i in IndustryType] else IndustryType.GENERAL
        multipliers = self.industry_risk_multipliers.get(industry_enum, {})

        # Match vulnerability type to multiplier
        vuln_type = vulnerability.get('title', '').lower()
        for vuln_pattern, multiplier in multipliers.items():
            if vuln_pattern in vuln_type:
                return multiplier

        return multipliers.get('default', 1.0)

    def _get_risk_level(self, risk_score: float) -> RiskLevel:
        """Convert risk score to risk level."""
        if risk_score >= 9.0:
            return RiskLevel.CRITICAL
        elif risk_score >= 7.0:
            return RiskLevel.HIGH
        elif risk_score >= 4.0:
            return RiskLevel.MEDIUM
        elif risk_score >= 2.0:
            return RiskLevel.LOW
        else:
            return RiskLevel.INFO

    def _calculate_detailed_remediation_priority(
        self,
        risk_score: float,
        business_impact: float,
        exploit_score: float,
        compliance_score: Dict[str, Any],
        business_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Calculate detailed remediation priority with SLA."""
        # Calculate priority score
        priority_score = (
            risk_score * 0.40 +
            business_impact * 10.0 * 0.35 +
            exploit_score * 10.0 * 0.15 +
            compliance_score['score'] * 10.0 * 0.10
        )

        # Adjust for business context
        if business_context.get('public_facing', False):
            priority_score += 1.0
        if business_context.get('compliance_required', False):
            priority_score += 0.5

        # Determine priority level and SLA
        now = utc_now()
        
        if priority_score >= 9.0:
            priority = RemediationPriority.P0_IMMEDIATE
            sla_hours = 24
            grace_hours = 0
        elif priority_score >= 7.0:
            priority = RemediationPriority.P1_URGENT
            sla_hours = 72
            grace_hours = 24
        elif priority_score >= 5.0:
            priority = RemediationPriority.P2_HIGH
            sla_hours = 168  # 1 week
            grace_hours = 48
        elif priority_score >= 3.0:
            priority = RemediationPriority.P3_MEDIUM
            sla_hours = 336  # 2 weeks
            grace_hours = 72
        else:
            priority = RemediationPriority.P4_LOW
            sla_hours = 720  # 1 month
            grace_hours = 168

        sla_deadline = now + timedelta(hours=sla_hours)
        recommended_fix_date = now + timedelta(hours=sla_hours // 2)
        grace_period_end = sla_deadline + timedelta(hours=grace_hours)

        return {
            'priority': priority.value,
            'priority_score': round(priority_score, 2),
            'sla_hours': sla_hours,
            'sla_deadline': sla_deadline.isoformat(),
            'recommended_fix_date': recommended_fix_date.isoformat(),
            'grace_period_end': grace_period_end.isoformat(),
            'business_justification': self._get_priority_justification(
                priority_score,
                risk_score,
                business_impact,
                exploit_score
            )
        }

    async def _perform_cost_benefit_analysis(
        self,
        vulnerability: Dict[str, Any],
        business_context: Dict[str, Any],
        risk_score: float
    ) -> Dict[str, Any]:
        """Perform cost-benefit analysis for remediation."""
        # Estimate potential loss
        base_loss = business_context.get('estimated_breach_cost', 50000)  # Default $50k
        
        # Scale by risk score
        potential_loss = base_loss * (risk_score / 10.0)
        
        # Industry multiplier
        industry = business_context.get('industry', IndustryType.GENERAL)
        industry_loss_multipliers = {
            IndustryType.FINANCIAL: 3.0,
            IndustryType.HEALTHCARE: 2.5,
            IndustryType.ECOMMERCE: 2.0,
            IndustryType.GOVERNMENT: 2.2,
            IndustryType.TECHNOLOGY: 1.8,
            IndustryType.EDUCATION: 1.5,
            IndustryType.GENERAL: 1.0
        }
        
        industry_enum = IndustryType(industry) if industry in [i.value for i in IndustryType] else IndustryType.GENERAL
        potential_loss *= industry_loss_multipliers.get(industry_enum, 1.0)
        
        # Estimate remediation cost
        severity = vulnerability.get('severity', 'medium').lower()
        base_fix_costs = {
            'critical': 15000,
            'high': 10000,
            'medium': 5000,
            'low': 2000,
            'info': 500
        }
        remediation_cost = base_fix_costs.get(severity, 5000)
        
        # ROI calculation
        roi = ((potential_loss - remediation_cost) / remediation_cost) * 100 if remediation_cost > 0 else 0
        
        # Break-even point (how many incidents to justify fix)
        break_even = remediation_cost / potential_loss if potential_loss > 0 else float('inf')
        
        return {
            'potential_loss': round(potential_loss, 2),
            'remediation_cost': round(remediation_cost, 2),
            'roi_percentage': round(roi, 2),
            'break_even_incidents': round(break_even, 2),
            'net_benefit': round(potential_loss - remediation_cost, 2),
            'recommendation': 'IMMEDIATE FIX' if roi > 100 else 'SCHEDULE FIX' if roi > 0 else 'EVALUATE ALTERNATIVES',
            'cost_breakdown': {
                'engineering_hours': round(remediation_cost * 0.6, 2),
                'testing_hours': round(remediation_cost * 0.2, 2),
                'deployment_cost': round(remediation_cost * 0.15, 2),
                'contingency': round(remediation_cost * 0.05, 2)
            }
        }

    async def _generate_enhanced_recommendations(
        self,
        vulnerability: Dict[str, Any],
        business_context: Dict[str, Any],
        mitre_techniques: List[Dict[str, Any]],
        risk_score: float,
        compliance_impact: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate comprehensive, prioritized recommendations."""
        recommendations = []
        
        # Immediate actions for high-risk vulnerabilities
        if risk_score >= 7.0:
            recommendations.append({
                'priority': 'critical',
                'category': 'Immediate Action',
                'action': 'Isolate affected systems',
                'details': 'Temporarily isolate or restrict access to affected systems until patched',
                'estimated_effort': '2-4 hours',
                'resources_required': ['Security team', 'Network admin'],
                'success_metrics': ['System isolated', 'Access logs reviewed']
            })
        
        # Technical remediation
        vuln_type = vulnerability.get('title', '').lower()
        if 'injection' in vuln_type:
            recommendations.append({
                'priority': 'high',
                'category': 'Code Fix',
                'action': 'Implement parameterized queries',
                'details': 'Replace dynamic SQL with prepared statements and parameterized queries',
                'estimated_effort': '1-3 days',
                'resources_required': ['Developer', 'Code reviewer'],
                'code_example': 'Use PreparedStatement or ORM frameworks',
                'success_metrics': ['Code review passed', 'Security test passed']
            })
        
        if 'xss' in vuln_type or 'cross-site' in vuln_type:
            recommendations.append({
                'priority': 'high',
                'category': 'Input Validation',
                'action': 'Implement output encoding',
                'details': 'Use context-aware output encoding for all user inputs',
                'estimated_effort': '2-5 days',
                'resources_required': ['Developer', 'Security engineer'],
                'code_example': 'Use OWASP Java Encoder or similar library',
                'success_metrics': ['All inputs sanitized', 'WAF rules updated']
            })
        
        if 'auth' in vuln_type:
            recommendations.append({
                'priority': 'high',
                'category': 'Authentication',
                'action': 'Implement MFA',
                'details': 'Deploy multi-factor authentication for all user accounts',
                'estimated_effort': '1-2 weeks',
                'resources_required': ['Security team', 'Identity management'],
                'success_metrics': ['MFA enabled', 'User adoption >90%']
            })
        
        # Compliance-driven recommendations
        for framework, impact_data in compliance_impact.get('frameworks', {}).items():
            if impact_data['matched_requirements']:
                recommendations.append({
                    'priority': 'medium',
                    'category': 'Compliance',
                    'action': f'Address {framework.upper()} requirements',
                    'details': f"Remediate to meet {framework.upper()} compliance requirements",
                    'estimated_effort': '1-2 weeks',
                    'resources_required': ['Compliance officer', 'Security team'],
                    'requirements': [req['requirement'] for req in impact_data['matched_requirements']],
                    'success_metrics': [f'{framework.upper()} audit passed']
                })
        
        # MITRE-based defensive recommendations
        if mitre_techniques:
            tactics = set([t.get('tactic', '') for t in mitre_techniques])
            for tactic in tactics:
                if tactic == 'Initial Access':
                    recommendations.append({
                        'priority': 'medium',
                        'category': 'Detection & Prevention',
                        'action': 'Deploy perimeter defenses',
                        'details': 'Implement WAF rules and intrusion detection systems',
                        'estimated_effort': '3-5 days',
                        'resources_required': ['Security engineer', 'Network team'],
                        'success_metrics': ['WAF deployed', 'Alerts configured']
                    })
        
        # Monitoring and detection
        recommendations.append({
            'priority': 'medium',
            'category': 'Monitoring',
            'action': 'Enhance detection capabilities',
            'details': 'Configure SIEM alerts and monitoring for exploitation attempts',
            'estimated_effort': '2-3 days',
            'resources_required': ['SOC analyst', 'Security engineer'],
            'success_metrics': ['Alerts configured', 'Baseline established']
        })
        
        # Long-term strategic recommendations
        recommendations.append({
            'priority': 'low',
            'category': 'Strategic',
            'action': 'Security training',
            'details': 'Conduct targeted security training for development team',
            'estimated_effort': '1 week',
            'resources_required': ['Security team', 'Training coordinator'],
            'success_metrics': ['Team trained', 'Secure coding practices adopted']
        })
        
        return recommendations

    def _suggest_resource_allocation(
        self,
        risk_score: float,
        business_context: Dict[str, Any],
        cost_benefit: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Suggest resource allocation based on risk and business context."""
        # Base team size on risk score
        if risk_score >= 9.0:
            team_size = 'Large (6-8 people)'
            skill_levels = ['Senior security engineer', 'Security architect', 'Developers', 'QA engineers']
            timeline = '24-48 hours'
        elif risk_score >= 7.0:
            team_size = 'Medium (3-5 people)'
            skill_levels = ['Security engineer', 'Senior developer', 'QA engineer']
            timeline = '3-7 days'
        elif risk_score >= 4.0:
            team_size = 'Small (2-3 people)'
            skill_levels = ['Developer', 'Security analyst']
            timeline = '1-2 weeks'
        else:
            team_size = 'Minimal (1-2 people)'
            skill_levels = ['Developer']
            timeline = '2-4 weeks'
        
        return {
            'team_size': team_size,
            'required_skills': skill_levels,
            'estimated_timeline': timeline,
            'budget_allocation': cost_benefit['remediation_cost'],
            'parallel_work_possible': risk_score < 7.0,
            'external_help_recommended': risk_score >= 9.0 or cost_benefit['remediation_cost'] > 20000,
            'sprint_priority': 'P0' if risk_score >= 8.0 else 'P1' if risk_score >= 6.0 else 'Backlog'
        }

    def _get_business_impact_factors(
        self,
        vulnerability: Dict[str, Any],
        business_context: Dict[str, Any]
    ) -> List[str]:
        """Get list of business impact factors."""
        factors = []
        
        if business_context.get('sensitive_data'):
            factors.append('Sensitive Data Exposure Risk')
        if business_context.get('customer_facing'):
            factors.append('Customer-Facing System Impact')
        if business_context.get('revenue_impact'):
            factors.append('Direct Revenue Impact')
        if business_context.get('compliance_required'):
            factors.append('Compliance Violations Possible')
        if business_context.get('brand_impact'):
            factors.append('Brand Reputation Risk')
        if business_context.get('operational_critical'):
            factors.append('Business Operations Disruption')
        
        return factors

    def _assess_reputation_impact(self, business_context: Dict[str, Any]) -> str:
        """Assess potential reputation impact."""
        if business_context.get('public_company'):
            return 'HIGH - Stock price impact, media coverage likely'
        elif business_context.get('customer_facing'):
            return 'MEDIUM - Customer trust erosion, negative reviews'
        else:
            return 'LOW - Limited external visibility'

    def _assess_operational_impact(
        self,
        vulnerability: Dict[str, Any],
        business_context: Dict[str, Any]
    ) -> str:
        """Assess operational impact."""
        if business_context.get('operational_critical'):
            return 'CRITICAL - Business operations may halt'
        elif 'availability' in vulnerability.get('title', '').lower():
            return 'HIGH - Service disruption likely'
        else:
            return 'MODERATE - Degraded performance possible'

    def _identify_attack_vectors(self, vulnerability: Dict[str, Any]) -> List[str]:
        """Identify possible attack vectors."""
        vectors = []
        vuln_text = f"{vulnerability.get('title', '')} {vulnerability.get('description', '')}".lower()
        
        if 'remote' in vuln_text or 'network' in vuln_text:
            vectors.append('Network - Remote exploitation possible')
        if 'local' in vuln_text:
            vectors.append('Local - Requires local access')
        if 'web' in vuln_text or 'http' in vuln_text:
            vectors.append('Web - HTTP/HTTPS exploitation')
        if 'api' in vuln_text:
            vectors.append('API - REST/GraphQL endpoint exploitation')
        if 'authenticated' in vuln_text:
            vectors.append('Authenticated - Requires valid credentials')
        else:
            vectors.append('Unauthenticated - No credentials required')
        
        return vectors if vectors else ['Unknown attack vector']

    def _identify_attack_prerequisites(self, vulnerability: Dict[str, Any]) -> List[str]:
        """Identify attack prerequisites."""
        prereqs = []
        vuln_text = f"{vulnerability.get('title', '')} {vulnerability.get('description', '')}".lower()
        
        if 'authenticated' in vuln_text or 'login' in vuln_text:
            prereqs.append('Valid user credentials')
        if 'privilege' in vuln_text:
            prereqs.append('Elevated privileges')
        if 'user interaction' in vuln_text or 'click' in vuln_text:
            prereqs.append('User interaction required')
        if 'social engineering' in vuln_text:
            prereqs.append('Social engineering component')
        
        return prereqs if prereqs else ['No special prerequisites']

    def _get_compliance_risk_level(self, score: float) -> str:
        """Get compliance risk level."""
        if score >= 0.8:
            return 'CRITICAL - Major compliance violations'
        elif score >= 0.6:
            return 'HIGH - Significant compliance issues'
        elif score >= 0.4:
            return 'MEDIUM - Moderate compliance concerns'
        elif score >= 0.2:
            return 'LOW - Minor compliance gaps'
        else:
            return 'MINIMAL - No significant compliance impact'

    def _get_regulatory_requirements(
        self,
        vulnerability: Dict[str, Any],
        business_context: Dict[str, Any]
    ) -> List[str]:
        """Get applicable regulatory requirements."""
        requirements = []
        
        frameworks = business_context.get('compliance_frameworks', [])
        if 'pci_dss' in frameworks:
            requirements.append('PCI DSS - Must report breach within 24 hours')
        if 'gdpr' in frameworks:
            requirements.append('GDPR - 72-hour breach notification required')
        if 'hipaa' in frameworks:
            requirements.append('HIPAA - Breach notification to HHS required')
        if 'sox' in frameworks:
            requirements.append('SOX - Material weakness reporting required')
        
        return requirements

    def _get_industry_concerns(self, vulnerability: Dict[str, Any], industry: str) -> List[str]:
        """Get industry-specific concerns."""
        industry_enum = IndustryType(industry) if industry in [i.value for i in IndustryType] else IndustryType.GENERAL
        
        concerns_map = {
            IndustryType.FINANCIAL: [
                'Payment card data exposure',
                'Wire transfer fraud risk',
                'Regulatory penalties (FFIEC, FINRA)'
            ],
            IndustryType.HEALTHCARE: [
                'PHI/ePHI exposure',
                'HIPAA violation penalties',
                'Patient safety concerns'
            ],
            IndustryType.ECOMMERCE: [
                'Payment processing disruption',
                'Customer data breach',
                'Revenue loss during outage'
            ],
            IndustryType.GOVERNMENT: [
                'Classified data exposure',
                'National security implications',
                'Public trust erosion'
            ],
            IndustryType.TECHNOLOGY: [
                'Intellectual property theft',
                'Source code exposure',
                'Customer trust in platform'
            ],
            IndustryType.EDUCATION: [
                'Student data privacy (FERPA)',
                'Research data integrity',
                'Academic reputation'
            ]
        }
        
        return concerns_map.get(industry_enum, ['General security concerns'])

    def _get_priority_justification(
        self,
        priority_score: float,
        risk_score: float,
        business_impact: float,
        exploit_score: float
    ) -> str:
        """Generate business justification for priority level."""
        justifications = []
        
        if risk_score >= 8.0:
            justifications.append(f'Critical risk score ({risk_score:.1f}/10)')
        if business_impact >= 0.7:
            justifications.append('High business impact')
        if exploit_score >= 0.7:
            justifications.append('Active exploitation detected')
        
        if justifications:
            return f"Priority justified by: {', '.join(justifications)}"
        else:
            return 'Standard prioritization based on risk metrics'
