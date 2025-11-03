"""
API endpoints for enhanced risk analysis and business context.
"""
from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from enum import Enum
import logging

from app.database.supabase_client import supabase
from app.services.intelligence.enhanced_risk_analyzer import (
    EnhancedRiskAnalyzer,
    IndustryType,
    RiskLevel,
    RemediationPriority
)
from sqlalchemy.orm import Session
from app.database import get_db
from app.services.intelligence_mapping.mitre_mapper import MITREMapper

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/risk-analysis", tags=["Risk Analysis"])


class BusinessContextInput(BaseModel):
    """Business context for risk analysis."""
    asset_criticality: str = Field(..., description="Asset criticality: critical, high, medium, low")
    industry: str = Field(default="technology", description="Industry type")
    sensitive_data: bool = Field(default=False, description="Contains sensitive data")
    customer_facing: bool = Field(default=False, description="Customer-facing system")
    revenue_impact: bool = Field(default=False, description="Has revenue impact")
    compliance_frameworks: List[str] = Field(default=["owasp_top_10"], description="Applicable compliance frameworks")
    data_classification: str = Field(default="internal", description="Data classification level")
    public_facing: bool = Field(default=False, description="Publicly accessible")
    estimated_breach_cost: float = Field(default=50000, description="Estimated breach cost in USD")
    revenue_criticality: str = Field(default="medium", description="Revenue criticality level")
    compliance_required: bool = Field(default=True, description="Compliance required")
    operational_critical: bool = Field(default=False, description="Operationally critical system")
    brand_impact: bool = Field(default=False, description="Has brand reputation impact")
    public_company: bool = Field(default=False, description="Is a public company")


class RiskAnalysisRequest(BaseModel):
    """Request for comprehensive risk analysis."""
    scan_id: str = Field(..., description="Scan identifier")
    vulnerability_id: Optional[int] = Field(None, description="Specific vulnerability ID to analyze")
    business_context: BusinessContextInput = Field(..., description="Business context")


class RiskAnalysisResponse(BaseModel):
    """Response with comprehensive risk analysis."""
    risk_score: float
    risk_level: str
    remediation_priority: Dict[str, Any]
    business_impact: Dict[str, Any]
    compliance_impact: Dict[str, Any]
    exploit_analysis: Dict[str, Any]
    attack_surface: Dict[str, Any]
    timeline: Dict[str, Any]
    cost_benefit_analysis: Dict[str, Any]
    recommendations: List[Dict[str, Any]]
    resource_allocation: Dict[str, Any]
    industry_context: Dict[str, Any]
    mitre_context: Dict[str, Any]


@router.post("/comprehensive", response_model=RiskAnalysisResponse)
async def analyze_comprehensive_risk(
    request: RiskAnalysisRequest,
    db: Session = Depends(get_db)
):
    """
    Perform comprehensive risk analysis with business context.
    
    This endpoint provides:
    - Multi-factor risk scoring
    - Business impact assessment
    - Compliance impact analysis
    - Cost-benefit analysis
    - Prioritized recommendations
    - Resource allocation suggestions
    - Industry-specific risk factors
    """
    try:
        # Get scan and vulnerability data
        scan_result = supabase.client.table('owasp_scans').select('*').eq('scan_id', request.scan_id).execute()
        if not scan_result.data:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        scan_data = scan_result.data[0]
        
        # Get vulnerabilities
        if request.vulnerability_id:
            vuln_result = supabase.client.table('owasp_vulnerabilities').select('*').eq('vulnerability_id', request.vulnerability_id).execute()
            if not vuln_result.data:
                raise HTTPException(status_code=404, detail="Vulnerability not found")
            vulnerability = vuln_result.data[0]
        else:
            # Get highest severity vulnerability
            vulns_result = supabase.client.table('owasp_vulnerabilities').select('*').eq('scan_id', request.scan_id).order('cvss_score', desc=True).limit(1).execute()
            if not vulns_result.data:
                raise HTTPException(status_code=404, detail="No vulnerabilities found")
            vulnerability = vulns_result.data[0]
        
        # Get MITRE mapping
        mitre_mapper = MITREMapper(db)
        description = f"{vulnerability.get('title', '')} {vulnerability.get('description', '')}"
        mitre_mapping = await mitre_mapper.map_vulnerability(description, vulnerability.get('cve_id'))
        mitre_techniques = mitre_mapping.get('techniques', [])
        
        # Perform comprehensive risk analysis
        risk_analyzer = EnhancedRiskAnalyzer()
        
        business_context = request.business_context.dict()
        
        analysis = await risk_analyzer.analyze_comprehensive_risk(
            vulnerability=vulnerability,
            business_context=business_context,
            mitre_techniques=mitre_techniques,
            threat_intel=None  # Can be enhanced with real-time threat intel API
        )
        
        return RiskAnalysisResponse(**analysis)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Risk analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"Risk analysis failed: {str(e)}")


@router.get("/scan/{scan_id}/summary")
async def get_scan_risk_summary(scan_id: str):
    """
    Get risk summary for an entire scan.
    
    Provides aggregated risk metrics across all vulnerabilities.
    """
    try:
        # Get scan data
        scan_result = supabase.client.table('owasp_scans').select('*').eq('scan_id', scan_id).execute()
        if not scan_result.data:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        scan_data = scan_result.data[0]
        
        # Get all vulnerabilities
        vulns_result = supabase.client.table('owasp_vulnerabilities').select('*').eq('scan_id', scan_id).execute()
        vulnerabilities = vulns_result.data
        
        # Calculate aggregated metrics
        total_vulns = len(vulnerabilities)
        severity_distribution = {
            'critical': len([v for v in vulnerabilities if v.get('severity', '').lower() == 'critical']),
            'high': len([v for v in vulnerabilities if v.get('severity', '').lower() == 'high']),
            'medium': len([v for v in vulnerabilities if v.get('severity', '').lower() == 'medium']),
            'low': len([v for v in vulnerabilities if v.get('severity', '').lower() == 'low']),
            'info': len([v for v in vulnerabilities if v.get('severity', '').lower() == 'info'])
        }
        
        avg_cvss = sum(v.get('cvss_score', 0) or 0 for v in vulnerabilities) / total_vulns if total_vulns > 0 else 0
        
        # Get remediation strategies if available
        remediation_strategies = scan_data.get('remediation_strategies', {})
        
        return {
            'scan_id': scan_id,
            'total_vulnerabilities': total_vulns,
            'severity_distribution': severity_distribution,
            'average_cvss_score': round(avg_cvss, 2),
            'risk_score': scan_data.get('risk_score', 0),
            'risk_level': scan_data.get('risk_level', 'Unknown'),
            'remediation_strategies': remediation_strategies,
            'mitre_mapping': scan_data.get('mitre_mapping', []),
            'ai_analysis': scan_data.get('ai_analysis', []),
            'scan_status': scan_data.get('status'),
            'scan_completed_at': scan_data.get('completed_at'),
            'target_url': scan_data.get('target_url')
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get scan risk summary: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get scan risk summary: {str(e)}")


@router.get("/recommendations/{scan_id}")
async def get_prioritized_recommendations(
    scan_id: str,
    priority_filter: Optional[str] = Query(None, description="Filter by priority: critical, high, medium, low"),
    category_filter: Optional[str] = Query(None, description="Filter by category")
):
    """
    Get prioritized recommendations for a scan.
    
    Returns actionable recommendations sorted by priority.
    """
    try:
        # Get scan data
        scan_result = supabase.client.table('owasp_scans').select('*').eq('scan_id', scan_id).execute()
        if not scan_result.data:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        scan_data = scan_result.data[0]
        remediation_strategies = scan_data.get('remediation_strategies', {})
        recommendations = remediation_strategies.get('recommendations', [])
        
        # Apply filters
        if priority_filter:
            recommendations = [r for r in recommendations if r.get('priority', '').lower() == priority_filter.lower()]
        
        if category_filter:
            recommendations = [r for r in recommendations if r.get('category', '').lower() == category_filter.lower()]
        
        # Sort by priority
        priority_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        recommendations.sort(key=lambda x: priority_order.get(x.get('priority', 'low').lower(), 99))
        
        return {
            'scan_id': scan_id,
            'total_recommendations': len(recommendations),
            'recommendations': recommendations,
            'priority_matrix': remediation_strategies.get('priority_matrix'),
            'timeline': remediation_strategies.get('timeline'),
            'resource_allocation': remediation_strategies.get('resource_allocation')
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get recommendations: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get recommendations: {str(e)}")


@router.get("/cost-benefit/{scan_id}")
async def get_cost_benefit_analysis(scan_id: str):
    """
    Get cost-benefit analysis for scan remediation.
    
    Provides ROI calculations and financial justification for fixes.
    """
    try:
        # Get scan data
        scan_result = supabase.client.table('owasp_scans').select('*').eq('scan_id', scan_id).execute()
        if not scan_result.data:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        scan_data = scan_result.data[0]
        remediation_strategies = scan_data.get('remediation_strategies', {})
        cost_benefit = remediation_strategies.get('cost_benefit', {})
        
        return {
            'scan_id': scan_id,
            'cost_benefit_analysis': cost_benefit,
            'risk_score': scan_data.get('risk_score'),
            'risk_level': scan_data.get('risk_level'),
            'recommendation': cost_benefit.get('recommendation', 'Evaluate based on risk'),
            'financial_summary': {
                'potential_loss': cost_benefit.get('potential_loss', 0),
                'remediation_cost': cost_benefit.get('remediation_cost', 0),
                'net_benefit': cost_benefit.get('net_benefit', 0),
                'roi_percentage': cost_benefit.get('roi_percentage', 0)
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get cost-benefit analysis: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get cost-benefit analysis: {str(e)}")


@router.get("/industry-templates")
async def get_industry_risk_templates():
    """
    Get industry-specific risk templates and multipliers.
    
    Useful for understanding industry-specific risk factors.
    """
    return {
        'industries': [industry.value for industry in IndustryType],
        'risk_levels': [level.value for level in RiskLevel],
        'remediation_priorities': [priority.value for priority in RemediationPriority],
        'compliance_frameworks': [
            'pci_dss',
            'owasp_top_10',
            'iso_27001',
            'gdpr',
            'hipaa',
            'sox',
            'nist'
        ],
        'asset_criticality_levels': ['critical', 'high', 'medium', 'low'],
        'data_classifications': ['restricted', 'confidential', 'internal', 'public']
    }
