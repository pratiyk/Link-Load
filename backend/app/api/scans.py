"""
Comprehensive Security Scanning API Endpoints
Handles all security scanning operations including OWASP ZAP, Nuclei, and Wapiti
"""
import logging
import uuid
from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks, WebSocket, WebSocketDisconnect
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, HttpUrl, Field
from datetime import datetime, timezone

from app.services.comprehensive_scanner import ComprehensiveScanner
from app.core.security import get_current_user
from app.database.supabase_client import supabase
from app.core.config import settings
from app.services.llm_service import llm_service
from app.core.authorization import (
    verify_scan_ownership,
    require_authenticated_user,
    get_user_id,
    AccessDeniedException,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/scans", tags=["Comprehensive Scanning"])

# ============================================================================
# REQUEST/RESPONSE MODELS
# ============================================================================

class ScanOptions(BaseModel):
    """Scan configuration options"""
    enable_ai_analysis: bool = True
    enable_mitre_mapping: bool = True
    include_low_risk: bool = False
    deep_scan: bool = False
    timeout_minutes: int = 30
    business_context: Optional[str] = None
    compliance_frameworks: Optional[List[str]] = None


class StartScanRequest(BaseModel):
    """Request to start a new scan"""
    target_url: HttpUrl = Field(..., description="URL to scan")
    scan_types: List[str] = Field(
        default=["owasp", "nuclei", "wapiti"],
        description="Types of scanners to use: owasp, nuclei, wapiti"
    )
    options: ScanOptions = Field(default_factory=ScanOptions)


class ScanInfo(BaseModel):
    """Information about a scan"""
    scan_id: str
    target_url: str
    status: str
    progress: int
    current_stage: str
    started_at: datetime
    completed_at: Optional[datetime] = None


class VulnerabilityInfo(BaseModel):
    """Information about a vulnerability"""
    id: str
    title: str
    description: str
    severity: str
    cvss_score: float
    location: str
    recommendation: Optional[str] = None
    mitre_techniques: Optional[List[str]] = None


class RiskAssessment(BaseModel):
    """Risk assessment for vulnerabilities"""
    overall_risk_score: float = 0.0
    risk_level: str = "Unknown"
    vulnerability_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    risk_factors: Optional[List[Dict[str, Any]]] = None


class AIAnalysisResult(BaseModel):
    """AI-powered analysis results"""
    title: str
    description: Optional[str] = None
    recommendations: Optional[List[str]] = None
    remediation_priority: Optional[str] = None
    # Additional fields that may come from various sources
    severity: Optional[str] = None
    summary: Optional[str] = None
    impact: Optional[str] = None


class ScanResultsResponse(BaseModel):
    """Complete scan results response"""
    scan_id: str
    target_url: str
    status: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    vulnerabilities: List[VulnerabilityInfo]
    risk_assessment: RiskAssessment
    mitre_mapping: Optional[List[Dict[str, Any]]] = None
    ai_analysis: Optional[List[AIAnalysisResult]] = None
    remediation_strategies: Optional[Dict[str, Any]] = None
    executive_summary: Optional[str] = None
    # Threat Intelligence data from external APIs
    threat_intel: Optional[Dict[str, Any]] = None
    # Scan configuration info
    scan_mode: Optional[str] = None  # 'quick', 'standard', or 'deep'
    scan_types: Optional[List[str]] = None  # List of scanners used
    options: Optional[Dict[str, Any]] = None  # Scan options used
    # Optional diagnostics when debug=1 is requested
    debug: Optional[Dict[str, Any]] = None


class StartScanResponse(BaseModel):
    """Response for starting a scan"""
    scan_id: str
    message: str = "Scan started successfully"
    status_url: str


# ============================================================================
# GLOBAL INSTANCES
# ============================================================================

scanner = ComprehensiveScanner()
active_connections: Dict[str, WebSocket] = {}


# ============================================================================
# API ENDPOINTS
# ============================================================================

@router.post("/comprehensive/start", response_model=StartScanResponse)
async def start_comprehensive_scan(
    request: StartScanRequest,
    background_tasks: BackgroundTasks,
    current_user = Depends(get_current_user)
):
    """
    Start a comprehensive security scan
    
    Orchestrates multiple scanners (OWASP ZAP, Nuclei, Wapiti) for comprehensive
    vulnerability assessment with AI-powered analysis.
    """
    logger.info(f"[DEBUG] Received scan request: target_url={request.target_url}, scan_types={request.scan_types}")
    try:
        # Generate unique scan ID
        scan_id = f"scan_{uuid.uuid4().hex[:12]}"
        
        # Create scan record (explicitly require authenticated user)
        user_id = current_user.id
        scan_record = {
            "scan_id": scan_id,
            "user_id": user_id,
            "target_url": str(request.target_url),
            "scan_types": request.scan_types,
            "status": "pending",
            "progress": 0,
            "current_stage": "Initializing",
            "started_at": datetime.now(timezone.utc).isoformat(),
            "options": request.options.dict()
        }
        
        supabase.create_scan(scan_record)
        
        # Start scan in background using sync wrapper for proper execution
        logger.info(f"[DEBUG] Adding background task for scan {scan_id}")
        background_tasks.add_task(
            _run_comprehensive_scan_sync,
            scan_id,
            str(request.target_url),
            request.scan_types,
            request.options.dict(),
            user_id  # Use the user_id we already determined above
        )
        logger.info(f"[DEBUG] Background task added for scan {scan_id}")
        
        logger.info(f"Scan {scan_id} initiated for {request.target_url}")
        
        return StartScanResponse(
            scan_id=scan_id,
            status_url=f"{settings.API_PREFIX}/scans/comprehensive/{scan_id}/status"
        )
        
    except Exception as e:
        logger.error(f"Failed to start scan: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to start scan")


@router.get("/comprehensive/{scan_id}/status")
async def get_scan_status(
    scan_id: str,
    current_user = Depends(get_current_user)
):
    """Get the current status of a scan.
    
    SECURITY: Only the owner of the scan can retrieve its status.
    """
    try:
        # Require authentication and get user_id
        user_id = get_user_id(current_user)
        
        scan = supabase.fetch_scan(scan_id)
        
        # Verify ownership
        verify_scan_ownership(scan, user_id)
        
        return {
            "scan_id": scan_id,
            "status": scan.get("status"),
            "progress": scan.get("progress", 0),
            "current_stage": scan.get("current_stage", "Unknown"),
            "started_at": scan.get("started_at"),
            "completed_at": scan.get("completed_at")
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching scan status: {str(e)}")
        raise HTTPException(status_code=500, detail="Error fetching scan status")


def _normalize_vulnerability(v: Dict[str, Any]) -> VulnerabilityInfo:
    """Normalize vulnerability data from various scanner formats to VulnerabilityInfo format"""
    raw_score = v.get("cvss_score") or v.get("cvss") or 0.0
    try:
        cvss_score = float(raw_score)
    except (TypeError, ValueError):
        cvss_score = 0.0

    mitre_techniques = v.get("mitre_techniques") or []
    if isinstance(mitre_techniques, dict):
        mitre_techniques = list(mitre_techniques.values())

    raw_id = v.get("vuln_id") or v.get("vulnerability_id") or v.get("id") or uuid.uuid4().hex[:8]
    if not isinstance(raw_id, str):
        raw_id = str(raw_id)

    return VulnerabilityInfo(
        id=raw_id,
        title=v.get("title") or v.get("name") or "Unknown",
        description=v.get("description") or "",
        severity=(v.get("severity") or "medium").lower(),
        cvss_score=cvss_score,
        location=v.get("location") or v.get("url") or v.get("path") or "",
        recommendation=v.get("recommendation") or v.get("solution") or None,
        mitre_techniques=mitre_techniques
    )


def _normalize_ai_analysis(analysis_list: Optional[List[Dict[str, Any]]]) -> Optional[List[AIAnalysisResult]]:
    """Normalize AI analysis data to ensure it matches the AIAnalysisResult schema."""
    if not analysis_list:
        return None
    
    normalized = []
    for item in analysis_list:
        if not isinstance(item, dict):
            continue
        
        # Extract title - required field
        title = item.get("title") or item.get("name") or "Analysis Result"
        
        # Extract description - may come from various fields
        description = (
            item.get("description") or 
            item.get("summary") or 
            item.get("analysis") or
            item.get("details") or
            None
        )
        
        # Extract recommendations - may be a list or a string
        recommendations = item.get("recommendations") or item.get("recommendation")
        if isinstance(recommendations, str):
            recommendations = [recommendations]
        elif not isinstance(recommendations, list):
            recommendations = None
        
        # Extract remediation priority - convert to string if it's an int
        remediation_priority = (
            item.get("remediation_priority") or 
            item.get("priority") or
            item.get("severity") or
            None
        )
        # Convert to string if not None (could be int like 1, 2, 3)
        if remediation_priority is not None:
            remediation_priority = str(remediation_priority)
        
        # Convert severity to string if not None
        severity = item.get("severity")
        if severity is not None:
            severity = str(severity)
        
        normalized.append(AIAnalysisResult(
            title=str(title) if title else "Analysis Result",
            description=str(description) if description else None,
            recommendations=recommendations,
            remediation_priority=remediation_priority,
            severity=severity,
            summary=str(item.get("summary")) if item.get("summary") else None,
            impact=str(item.get("impact")) if item.get("impact") else None
        ))
    
    return normalized if normalized else None


def _transform_remediation_strategies(
    strategies: Optional[Dict[str, Any]], 
    vulnerabilities: List[Dict[str, Any]]
) -> Optional[Dict[str, Any]]:
    """Transform remediation strategies to match the frontend expected format.
    
    Frontend expects:
    - priority_matrix: { critical: [...], high: [...], medium: [...], low: [...] }
    - timeline: { immediate_action: {...}, short_term: {...}, medium_term: {...} }
    - cost_benefit: { total_remediation_cost, potential_loss, net_benefit, roi_percentage, ... }
    - resource_allocation: { team_composition: {...}, estimated_timeline, budget_range }
    - recommendations: [{ title, description, priority, category, action_items, estimated_effort }, ...]
    """
    if not strategies:
        # Generate default remediation strategies from vulnerabilities if none exist
        if not vulnerabilities:
            return None
        
        strategies = {}
    
    transformed = {}
    
    # Transform priority_matrix - group vulnerabilities by severity
    priority_data = strategies.get('priority_matrix', {})
    if isinstance(priority_data, dict) and ('priority' in priority_data or 'sla_deadline' in priority_data):
        # Backend returned remediation_priority format, convert to priority matrix
        priority_matrix = {'critical': [], 'high': [], 'medium': [], 'low': []}
        for vuln in vulnerabilities:
            severity = (vuln.get('severity') or 'medium').lower()
            if severity in priority_matrix:
                priority_matrix[severity].append({
                    'title': vuln.get('title') or vuln.get('name') or 'Unknown Vulnerability',
                    'id': vuln.get('vuln_id') or vuln.get('id'),
                    'location': vuln.get('location') or vuln.get('url') or ''
                })
        transformed['priority_matrix'] = priority_matrix
    elif isinstance(priority_data, dict):
        transformed['priority_matrix'] = priority_data
    else:
        # Create default priority matrix from vulnerabilities
        priority_matrix = {'critical': [], 'high': [], 'medium': [], 'low': []}
        for vuln in vulnerabilities:
            severity = (vuln.get('severity') or 'medium').lower()
            if severity in priority_matrix:
                priority_matrix[severity].append({
                    'title': vuln.get('title') or vuln.get('name') or 'Unknown Vulnerability',
                    'id': vuln.get('vuln_id') or vuln.get('id'),
                    'location': vuln.get('location') or vuln.get('url') or ''
                })
        transformed['priority_matrix'] = priority_matrix
    
    # Transform timeline - convert SLA-based to phase-based
    timeline_data = strategies.get('timeline', {})
    if isinstance(timeline_data, dict) and ('sla_deadline' in timeline_data or 'recommended_fix_date' in timeline_data):
        # Backend returned SLA format, convert to phase-based timeline
        critical_vulns = [v for v in vulnerabilities if (v.get('severity') or '').lower() == 'critical']
        high_vulns = [v for v in vulnerabilities if (v.get('severity') or '').lower() == 'high']
        medium_vulns = [v for v in vulnerabilities if (v.get('severity') or '').lower() == 'medium']
        
        transformed['timeline'] = {
            'immediate_action': {
                'description': 'Address critical vulnerabilities immediately to prevent exploitation.',
                'items': [
                    {'title': v.get('title') or 'Critical Issue', 'estimated_hours': 4}
                    for v in critical_vulns[:5]
                ]
            } if critical_vulns else None,
            'short_term': {
                'description': 'Fix high severity issues within the first week.',
                'items': [
                    {'title': v.get('title') or 'High Priority Issue', 'estimated_hours': 8}
                    for v in high_vulns[:5]
                ]
            } if high_vulns else None,
            'medium_term': {
                'description': 'Address medium severity issues within 2-4 weeks.',
                'items': [
                    {'title': v.get('title') or 'Medium Priority Issue', 'estimated_hours': 4}
                    for v in medium_vulns[:5]
                ]
            } if medium_vulns else None
        }
        # Remove None values
        transformed['timeline'] = {k: v for k, v in transformed['timeline'].items() if v is not None}
    elif isinstance(timeline_data, dict) and timeline_data:
        transformed['timeline'] = timeline_data
    else:
        # Create default timeline from vulnerabilities
        critical_vulns = [v for v in vulnerabilities if (v.get('severity') or '').lower() == 'critical']
        high_vulns = [v for v in vulnerabilities if (v.get('severity') or '').lower() == 'high']
        
        timeline = {}
        if critical_vulns:
            timeline['immediate_action'] = {
                'description': 'Address critical vulnerabilities immediately.',
                'items': [{'title': v.get('title') or 'Critical Issue', 'estimated_hours': 4} for v in critical_vulns[:5]]
            }
        if high_vulns:
            timeline['short_term'] = {
                'description': 'Fix high severity issues within the first week.',
                'items': [{'title': v.get('title') or 'High Priority Issue', 'estimated_hours': 8} for v in high_vulns[:5]]
            }
        transformed['timeline'] = timeline
    
    # Transform cost_benefit - normalize field names
    cost_benefit_data = strategies.get('cost_benefit', {})
    if isinstance(cost_benefit_data, dict) and cost_benefit_data:
        transformed['cost_benefit'] = {
            'total_remediation_cost': cost_benefit_data.get('total_remediation_cost') or cost_benefit_data.get('remediation_cost') or cost_benefit_data.get('total_cost', 0),
            'potential_loss': cost_benefit_data.get('potential_loss') or cost_benefit_data.get('potential_breach_cost', 0),
            'net_benefit': cost_benefit_data.get('net_benefit', 0),
            'roi_percentage': cost_benefit_data.get('roi_percentage') or cost_benefit_data.get('roi', 0),
            'effort_hours': cost_benefit_data.get('effort_hours') or cost_benefit_data.get('estimated_hours', 0),
            'probability': cost_benefit_data.get('probability') or cost_benefit_data.get('breach_probability', 0),
            'recommendation': cost_benefit_data.get('recommendation') or cost_benefit_data.get('analysis_summary', '')
        }
    else:
        # Generate default cost-benefit from vulnerabilities
        # Costs in INR based on industry standards (IBM Cost of Data Breach 2024)
        critical_count = len([v for v in vulnerabilities if (v.get('severity') or '').lower() == 'critical'])
        high_count = len([v for v in vulnerabilities if (v.get('severity') or '').lower() == 'high'])
        medium_count = len([v for v in vulnerabilities if (v.get('severity') or '').lower() == 'medium'])
        low_count = len([v for v in vulnerabilities if (v.get('severity') or '').lower() == 'low'])
        info_count = len([v for v in vulnerabilities if (v.get('severity') or '').lower() == 'info'])
        
        # Remediation costs: Critical ₹50K, High ₹25K, Medium ₹12K, Low ₹5K, Info ₹2K
        estimated_cost = (critical_count * 50000) + (high_count * 25000) + (medium_count * 12000) + (low_count * 5000) + (info_count * 2000)
        
        # Potential loss: Risk-adjusted breach impact multipliers
        potential_loss = (critical_count * 750000) + (high_count * 250000) + (medium_count * 72000) + (low_count * 15000) + (info_count * 3000)
        
        transformed['cost_benefit'] = {
            'total_remediation_cost': estimated_cost,
            'potential_loss': potential_loss,
            'net_benefit': potential_loss - estimated_cost,
            'roi_percentage': ((potential_loss - estimated_cost) / max(estimated_cost, 1)) * 100 if estimated_cost > 0 else 0,
            'effort_hours': (critical_count * 16) + (high_count * 8) + (medium_count * 4) + (low_count * 2) + (info_count * 1),
            'recommendation': f'Prioritize fixing {critical_count} critical and {high_count} high severity vulnerabilities to reduce breach risk.'
        }
    
    # Transform resource_allocation - normalize structure
    resource_data = strategies.get('resource_allocation', {})
    if isinstance(resource_data, dict) and resource_data:
        transformed['resource_allocation'] = {
            'team_composition': resource_data.get('team_composition') or resource_data.get('team', {}),
            'estimated_timeline': resource_data.get('estimated_timeline') or resource_data.get('timeline', ''),
            'budget_range': resource_data.get('budget_range') or resource_data.get('budget', '')
        }
    else:
        # Generate default resource allocation
        total_vulns = len(vulnerabilities)
        critical_count = len([v for v in vulnerabilities if (v.get('severity') or '').lower() == 'critical'])
        
        transformed['resource_allocation'] = {
            'team_composition': {
                'Security Engineers': 1 + (1 if critical_count > 3 else 0),
                'Developers': 2 + (1 if total_vulns > 10 else 0),
                'QA Engineers': 1
            },
            'estimated_timeline': f'{max(1, total_vulns // 5)} - {max(2, total_vulns // 3)} weeks',
            'budget_range': f'${(total_vulns * 1000):,} - ${(total_vulns * 3000):,}'
        }
    
    # Transform recommendations - ensure proper structure
    recommendations_data = strategies.get('recommendations', [])
    if isinstance(recommendations_data, list) and recommendations_data:
        normalized_recs = []
        for rec in recommendations_data:
            if isinstance(rec, dict):
                normalized_recs.append({
                    'title': rec.get('title') or rec.get('name') or 'Recommendation',
                    'description': rec.get('description') or rec.get('recommendation') or rec.get('summary') or '',
                    'priority': rec.get('priority') or rec.get('severity') or 'medium',
                    'category': rec.get('category') or rec.get('type') or 'General',
                    'action_items': rec.get('action_items') or rec.get('steps') or [],
                    'estimated_effort': rec.get('estimated_effort') or rec.get('effort') or ''
                })
            elif isinstance(rec, str):
                normalized_recs.append({
                    'title': rec[:50] + '...' if len(rec) > 50 else rec,
                    'description': rec,
                    'priority': 'medium',
                    'category': 'General',
                    'action_items': [],
                    'estimated_effort': ''
                })
        transformed['recommendations'] = normalized_recs
    else:
        # Generate default recommendations from vulnerabilities
        recommendations = []
        severity_groups = {}
        for vuln in vulnerabilities:
            severity = (vuln.get('severity') or 'medium').lower()
            if severity not in severity_groups:
                severity_groups[severity] = []
            severity_groups[severity].append(vuln)
        
        for severity, vulns_list in sorted(severity_groups.items(), key=lambda x: ['critical', 'high', 'medium', 'low', 'info'].index(x[0]) if x[0] in ['critical', 'high', 'medium', 'low', 'info'] else 99):
            recommendations.append({
                'title': f'Address {len(vulns_list)} {severity.title()} Severity Issues',
                'description': f'Review and remediate all {severity} severity vulnerabilities to improve overall security posture.',
                'priority': severity,
                'category': 'Vulnerability Remediation',
                'action_items': [v.get('recommendation') or f"Fix {v.get('title', 'vulnerability')}" for v in vulns_list[:3]],
                'estimated_effort': f'{len(vulns_list) * 2} - {len(vulns_list) * 4} hours'
            })
        
        transformed['recommendations'] = recommendations
    
    return transformed


@router.get("/comprehensive/{scan_id}/result", response_model=ScanResultsResponse)
async def get_scan_results(
    scan_id: str,
    debug: Optional[bool] = False,
    current_user = Depends(get_current_user)
):
    """Get the complete results of a scan.
    
    SECURITY: Only the owner of the scan can retrieve its results.
    """
    try:
        # Require authentication and get user_id
        user_id = get_user_id(current_user)
        
        # Fetch scan
        scan = supabase.fetch_scan(scan_id)
        logger.info(f"Fetched scan {scan_id}: status={scan.get('status')}, risk_score={scan.get('risk_score')}")
        
        # Verify ownership
        verify_scan_ownership(scan, user_id)
        
        # Fetch vulnerabilities
        vulns = supabase.fetch_vulnerabilities(scan_id)
        logger.info(f"Fetched {len(vulns)} vulnerabilities for scan {scan_id}")
        
        # Log vulnerability details for debugging
        if vulns:
            severity_counts = {}
            for v in vulns:
                sev = (v.get("severity") or "unknown").lower()
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
            logger.info(f"Vulnerability severity breakdown: {severity_counts}")
        
        # Transform remediation strategies to match frontend expected format
        transformed_strategies = _transform_remediation_strategies(
            scan.get("remediation_strategies"),
            vulns
        )
        
        # Determine scan mode from options
        scan_options = scan.get("options") or {}
        scan_types = scan.get("scan_types") or []
        
        # Infer scan mode from scan_types if not explicitly stored
        scan_mode = scan_options.get("scan_mode")
        if not scan_mode:
            # Infer from scan_types
            if set(scan_types) == {"nuclei"}:
                scan_mode = "quick"
            elif set(scan_types) == {"nuclei", "wapiti"} or set(scan_types) == {"wapiti", "nuclei"}:
                scan_mode = "standard"
            elif "owasp" in scan_types:
                scan_mode = "deep"
            else:
                scan_mode = "standard"  # Default
        
        # Build response
        return ScanResultsResponse(
            scan_id=scan_id,
            target_url=str(scan.get("target_url") or ""),
            status=str(scan.get("status") or "unknown"),
            started_at=scan.get("started_at") or datetime.now(timezone.utc),
            completed_at=scan.get("completed_at"),
            vulnerabilities=[
                _normalize_vulnerability(v)
                for v in vulns
            ],
            risk_assessment=RiskAssessment(
                overall_risk_score=scan.get("risk_score") or scan.get("overall_risk_score") or 0.0,
                risk_level=scan.get("risk_level") or "Unknown",
                vulnerability_count=len(vulns),
                critical_count=scan.get("critical_count") or len([v for v in vulns if (v.get("severity") or "").lower() == "critical"]),
                high_count=scan.get("high_count") or len([v for v in vulns if (v.get("severity") or "").lower() == "high"]),
                medium_count=scan.get("medium_count") or len([v for v in vulns if (v.get("severity") or "").lower() == "medium"]),
                low_count=scan.get("low_count") or len([v for v in vulns if (v.get("severity") or "").lower() == "low"]),
                info_count=scan.get("info_count") or len([v for v in vulns if (v.get("severity") or "").lower() == "info"]),
                risk_factors=scan.get("risk_factors")
            ),
            mitre_mapping=scan.get("mitre_mapping"),
            ai_analysis=_normalize_ai_analysis(scan.get("ai_analysis")),
            remediation_strategies=transformed_strategies,
            executive_summary=scan.get("executive_summary"),
            threat_intel=scan.get("threat_intel"),  # Include threat intelligence data
            scan_mode=scan_mode,
            scan_types=scan_types if scan_types else None,
            options=scan_options if scan_options else None,
            debug=scan.get("scanner_debug") if debug else None
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching scan results: {str(e)}")
        raise HTTPException(status_code=500, detail="Error fetching scan results")


@router.get("/comprehensive/list")
async def list_scans(
    skip: int = 0,
    limit: int = 10,
    status: Optional[str] = None,
    current_user = Depends(get_current_user)
):
    """List the current user's scans with optional filtering.
    
    SECURITY: Users can only retrieve their own scans.
    """
    try:
        # Require authentication and get user_id
        user_id = get_user_id(current_user)
        
        scans = supabase.get_user_scans(user_id, status, limit, skip)
        return {
            "scans": scans,
            "total": len(scans),
            "skip": skip,
            "limit": limit
        }
    except Exception as e:
        logger.error(f"Error listing scans: {str(e)}")
        raise HTTPException(status_code=500, detail="Error listing scans")


@router.get("/comprehensive/{scan_id}/summary")
async def generate_scan_summary(
    scan_id: str,
    current_user = Depends(get_current_user)
):
    """Generate or return cached executive summary for a scan using Groq LLM.
    
    SECURITY: Only the owner of the scan can retrieve its summary.
    """
    try:
        # Require authentication and get user_id
        user_id = get_user_id(current_user)
        
        scan = supabase.fetch_scan(scan_id)
        
        # Verify ownership
        verify_scan_ownership(scan, user_id)

        vulnerabilities = supabase.fetch_vulnerabilities(scan_id)

        # Return cached summary if available
        cached_summary = scan.get("executive_summary")
        if cached_summary:
            return {
                "scan_id": scan_id,
                "summary": cached_summary,
                "cached": True
            }

        risk_score = scan.get("risk_score") or scan.get("overall_risk_score") or 0.0
        try:
            risk_score_value = float(risk_score)
        except (TypeError, ValueError):
            risk_score_value = 0.0

        risk_level = scan.get("risk_level") or "Unknown"
        
        # Get threat intel data for comprehensive summary
        threat_intel = scan.get("threat_intel") or {}

        summary_text = await llm_service.generate_executive_summary(
            vulnerabilities,
            risk_score_value,
            risk_level,
            threat_intel
        )

        if summary_text:
            supabase.update_scan(scan_id, {"executive_summary": summary_text})

        return {
            "scan_id": scan_id,
            "summary": summary_text,
            "cached": False
        }

    except HTTPException:
        raise
    except ValueError as e:
        logger.error(f"LLM provider unavailable for summary: {e}")
        raise HTTPException(status_code=503, detail="LLM provider unavailable for summary generation")
    except Exception as e:
        logger.error(f"Failed to generate scan summary: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to generate scan summary")


@router.get("/comprehensive/{scan_id}")
async def get_scan_result_redirect(
    scan_id: str,
    current_user = Depends(get_current_user)
):
    """Alias for get_scan_results for backward compatibility.
    
    SECURITY: Enforces user ownership via get_scan_results.
    """
    return await get_scan_results(scan_id, debug=False, current_user=current_user)


@router.websocket("/ws/{scan_id}")
async def websocket_scan_updates(websocket: WebSocket, scan_id: str):
    """
    WebSocket endpoint for real-time scan progress updates
    
    Sends live updates about scan progress, stages, and final results.
    """
    await websocket.accept()
    active_connections[scan_id] = websocket
    result_sent = False
    
    try:
        while True:
            # Fetch current scan status
            scan = supabase.fetch_scan(scan_id)
            
            if scan:
                # Send progress update
                try:
                    await websocket.send_json({
                        "type": "progress",
                        "status": {
                            "scan_id": scan_id,
                            "progress": scan.get("progress", 0),
                            "current_stage": scan.get("current_stage"),
                            "status": scan.get("status")
                        }
                    })
                except Exception as send_err:
                    logger.debug(f"Failed to send progress update for scan {scan_id}: {send_err}")
                    break
                
                # Send results if scan is complete (only once)
                if scan.get("status") == "completed" and not result_sent:
                    try:
                        vulns = supabase.fetch_vulnerabilities(scan_id)
                        await websocket.send_json({
                            "type": "result",
                            "results": {
                                "scan_id": scan_id,
                                "status": "completed",
                                "vulnerabilities": vulns,
                                "risk_score": scan.get("risk_score"),
                                "risk_level": scan.get("risk_level")
                            }
                        })
                        result_sent = True
                        break
                    except Exception as send_err:
                        logger.debug(f"Failed to send result for scan {scan_id}: {send_err}")
                        break
            
            # Wait before next update
            import asyncio
            await asyncio.sleep(2)
            
    except WebSocketDisconnect:
        logger.debug(f"WebSocket disconnected for scan {scan_id}")
    except Exception as e:
        logger.error(f"WebSocket error for scan {scan_id}: {str(e)}")
    finally:
        if scan_id in active_connections:
            del active_connections[scan_id]
        try:
            await websocket.close(code=1000)
        except:
            pass


@router.post("/comprehensive/{scan_id}/cancel")
async def cancel_scan(
    scan_id: str,
    current_user = Depends(get_current_user)
):
    """Cancel an in-progress scan.
    
    SECURITY: Only the owner of the scan can cancel it.
    """
    try:
        # Require authentication and get user_id
        user_id = get_user_id(current_user)
        
        scan = supabase.fetch_scan(scan_id)
        
        # Verify ownership
        verify_scan_ownership(scan, user_id)
        
        # Update status
        supabase.update_scan(scan_id, {"status": "cancelled"})
        
        return {"message": "Scan cancelled successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error cancelling scan: {str(e)}")
        raise HTTPException(status_code=500, detail="Error cancelling scan")


@router.delete("/comprehensive/{scan_id}")
async def delete_scan(
    scan_id: str,
    current_user = Depends(get_current_user)
):
    """Permanently delete a scan and all its associated data.
    
    This action is irreversible. The scan record, all vulnerabilities,
    and any cached data will be permanently removed.
    
    SECURITY: Only the owner of the scan can delete it.
    """
    try:
        # Require authentication and get user_id
        user_id = get_user_id(current_user)
        
        # Fetch scan to verify it exists and ownership
        scan = supabase.fetch_scan(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        # Verify ownership
        verify_scan_ownership(scan, user_id)
        
        # Delete the scan and all associated data
        deleted = supabase.delete_scan(scan_id, user_id=user_id)
        
        if deleted:
            return {
                "message": "Scan deleted successfully",
                "scan_id": scan_id,
                "deleted": True
            }
        else:
            raise HTTPException(status_code=500, detail="Failed to delete scan")
            
    except HTTPException:
        raise
    except AccessDeniedException as e:
        raise HTTPException(status_code=403, detail=str(e))
    except Exception as e:
        logger.error(f"Error deleting scan {scan_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Error deleting scan")


@router.delete("/comprehensive/bulk")
async def delete_multiple_scans(
    scan_ids: List[str],
    current_user = Depends(get_current_user)
):
    """Permanently delete multiple scans.
    
    This action is irreversible. All scan records, vulnerabilities,
    and cached data will be permanently removed.
    
    SECURITY: Only scans owned by the current user will be deleted.
    """
    try:
        user_id = get_user_id(current_user)
        
        deleted_count = 0
        failed_ids = []
        
        for scan_id in scan_ids:
            try:
                # Verify ownership and delete
                scan = supabase.fetch_scan(scan_id)
                if scan:
                    verify_scan_ownership(scan, user_id)
                    if supabase.delete_scan(scan_id, user_id=user_id):
                        deleted_count += 1
                    else:
                        failed_ids.append(scan_id)
                else:
                    failed_ids.append(scan_id)
            except AccessDeniedException:
                failed_ids.append(scan_id)
            except Exception as e:
                logger.warning(f"Failed to delete scan {scan_id}: {e}")
                failed_ids.append(scan_id)
        
        return {
            "message": f"Deleted {deleted_count} scans",
            "deleted_count": deleted_count,
            "failed_ids": failed_ids
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in bulk delete: {str(e)}")
        raise HTTPException(status_code=500, detail="Error deleting scans")


# ============================================================================
# BACKGROUND TASKS
# ============================================================================

def _run_comprehensive_scan_sync(
    scan_id: str,
    target_url: str,
    scan_types: List[str],
    options: Dict[str, Any],
    user_id: str
):
    """Synchronous wrapper for comprehensive scan background task"""
    import asyncio
    import sys
    
    print(f"[BACKGROUND TASK] Starting sync wrapper for scan {scan_id}", file=sys.stderr, flush=True)
    
    async def _run_scan():
        try:
            print(f"[BACKGROUND TASK] Inside async _run_scan for {scan_id}", file=sys.stderr, flush=True)
            logger.info(f"[BACKGROUND] Starting comprehensive scan {scan_id} for {target_url}")
            logger.info(f"[BACKGROUND] Scan types: {scan_types}, Options: {options}")
            
            # Initialize and run scan
            print(f"[BACKGROUND TASK] Calling scanner.start_scan for {scan_id}", file=sys.stderr, flush=True)
            await scanner.start_scan(scan_id, target_url, scan_types, options)
            
            print(f"[BACKGROUND TASK] Scan {scan_id} completed successfully", file=sys.stderr, flush=True)
            logger.info(f"[BACKGROUND] Scan {scan_id} completed successfully")
            
        except Exception as e:
            print(f"[BACKGROUND TASK] Scan {scan_id} failed with error: {str(e)}", file=sys.stderr, flush=True)
            logger.error(f"[BACKGROUND] Scan {scan_id} failed: {str(e)}", exc_info=True)
            try:
                supabase.update_scan(scan_id, {
                    "status": "failed",
                    "error": str(e),
                    "completed_at": datetime.now(timezone.utc).isoformat()
                })
            except Exception as update_error:
                print(f"[BACKGROUND TASK] Failed to update scan status: {update_error}", file=sys.stderr, flush=True)
                logger.error(f"[BACKGROUND] Failed to update scan status: {update_error}")
    
    # Run the async function
    try:
        print(f"[BACKGROUND TASK] Creating event loop for scan {scan_id}", file=sys.stderr, flush=True)
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        print(f"[BACKGROUND TASK] Running event loop for scan {scan_id}", file=sys.stderr, flush=True)
        loop.run_until_complete(_run_scan())
        print(f"[BACKGROUND TASK] Event loop completed for scan {scan_id}", file=sys.stderr, flush=True)
    except Exception as e:
        print(f"[BACKGROUND TASK] Event loop error for scan {scan_id}: {e}", file=sys.stderr, flush=True)
        logger.error(f"[BACKGROUND] Event loop error for scan {scan_id}: {e}", exc_info=True)
    finally:
        loop.close()
        print(f"[BACKGROUND TASK] Event loop closed for scan {scan_id}", file=sys.stderr, flush=True)


async def _run_comprehensive_scan(
    scan_id: str,
    target_url: str,
    scan_types: List[str],
    options: Dict[str, Any],
    user_id: str
):
    """Background task to execute comprehensive scan"""
    try:
        logger.info(f"Starting comprehensive scan {scan_id} for {target_url}")
        
        # Initialize and run scan
        await scanner.start_scan(scan_id, target_url, scan_types, options)
        
        logger.info(f"Scan {scan_id} completed successfully")
        
    except Exception as e:
        logger.error(f"Scan {scan_id} failed: {str(e)}", exc_info=True)
        try:
            supabase.update_scan(scan_id, {
                "status": "failed",
                "error": str(e),
                "completed_at": datetime.now(timezone.utc).isoformat()
            })
        except Exception as update_error:
            logger.error(f"Failed to update scan status: {update_error}")
