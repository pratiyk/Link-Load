"""Enhanced API routes for vulnerability intelligence."""
from fastapi import APIRouter, Depends, HTTPException, Query, Request, WebSocket, status
from sqlalchemy.orm import Session
from typing import List, Optional, Dict, Any
from datetime import datetime
from app.database import get_db
from app.core.security import get_current_user_id
from app.core.rate_limiter import limiter
from app.models.vulnerability_models import VulnerabilityData
from app.models.threat_intel_models import (
    MITRETechnique,
    MITRETactic,
    ThreatIntelligence,
    RiskScore
)
from app.services.ml.risk_scoring import risk_engine
from pydantic import BaseModel, Field
import logging

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/intelligence", tags=["intelligence"])

class ThreatIntelResponse(BaseModel):
    """Threat intelligence response model."""
    id: int
    source: str
    threat_type: str
    name: Optional[str]
    description: Optional[str]
    confidence_score: float
    severity: float
    indicators: Dict[str, Any]
    references: List[str]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class RiskScoreResponse(BaseModel):
    """Risk score response model."""
    vulnerability_id: int
    base_score: float
    temporal_score: Optional[float]
    environmental_score: Optional[float]
    exploit_likelihood: Optional[float]
    impact_score: Optional[float]
    ml_confidence: float
    factors: Dict[str, Any]
    created_at: datetime

    class Config:
        from_attributes = True

class MITREMappingResponse(BaseModel):
    """MITRE mapping response model."""
    technique_id: str
    name: str
    description: Optional[str]
    tactics: List[str]
    similarity_score: float

    class Config:
        from_attributes = True

@router.get("/threat-intel/{vuln_id}", response_model=List[ThreatIntelResponse])
@limiter.limit("30/minute")
async def get_threat_intelligence(
    request: Request,
    vuln_id: int,
    db: Session = Depends(get_db),
    current_user_id: str = Depends(get_current_user_id)
):
    """Get threat intelligence data for a vulnerability."""
    try:
        # Verify vulnerability exists and belongs to user
        vuln = db.query(VulnerabilityData).filter(
            VulnerabilityData.id == vuln_id
        ).first()
        
        if not vuln:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Vulnerability not found"
            )
            
        threat_intel = db.query(ThreatIntelligence).filter(
            ThreatIntelligence.vulnerability_id == vuln_id
        ).all()
        
        return threat_intel
        
    except Exception as e:
        logger.error(f"Error fetching threat intelligence: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch threat intelligence"
        )

@router.get("/risk-score/{vuln_id}", response_model=RiskScoreResponse)
@limiter.limit("30/minute")
async def get_risk_score(
    request: Request,
    vuln_id: int,
    refresh: bool = False,
    db: Session = Depends(get_db),
    current_user_id: str = Depends(get_current_user_id)
):
    """Get or calculate risk score for a vulnerability."""
    try:
        vuln = db.query(VulnerabilityData).filter(
            VulnerabilityData.id == vuln_id
        ).first()
        
        if not vuln:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Vulnerability not found"
            )
            
        # Get existing score or calculate new one
        risk_score = db.query(RiskScore).filter(
            RiskScore.vulnerability_id == vuln_id
        ).first()
        
        if not risk_score or refresh:
            # Calculate new risk score
            score_data = risk_engine.calculate_risk_score(vuln)
            
            if not risk_score:
                risk_score = RiskScore(vulnerability_id=vuln_id)
                db.add(risk_score)
                
            # Update score fields
            risk_score.base_score = score_data["score"]
            risk_score.temporal_score = score_data.get("temporal_multiplier")
            risk_score.environmental_score = score_data.get("environmental_multiplier")
            risk_score.ml_confidence = score_data.get("confidence", 0.0)
            risk_score.factors = score_data.get("factors", {})
            
            db.commit()
            db.refresh(risk_score)
            
        return risk_score
        
    except Exception as e:
        logger.error(f"Error calculating risk score: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to calculate risk score"
        )

@router.get("/mitre-mapping/{vuln_id}", response_model=List[MITREMappingResponse])
@limiter.limit("30/minute")
async def get_mitre_mapping(
    request: Request,
    vuln_id: int,
    threshold: float = Query(0.7, ge=0.0, le=1.0),
    refresh: bool = False,
    db: Session = Depends(get_db),
    current_user_id: str = Depends(get_current_user_id)
):
    """Get MITRE ATT&CK mapping for a vulnerability."""
    try:
        vuln = db.query(VulnerabilityData).filter(
            VulnerabilityData.id == vuln_id
        ).first()
        
        if not vuln:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Vulnerability not found"
            )
            
        # Get existing mapping or calculate new one
        if not refresh and vuln.mitre_techniques:
            return [
                {
                    "technique_id": t.technique_id,
                    "name": t.name,
                    "description": t.description,
                    "tactics": [tactic.name for tactic in t.tactics],
                    "similarity_score": 1.0  # Exact match for existing mappings
                }
                for t in vuln.mitre_techniques
            ]
            
        # Calculate new mapping
        if not vuln.description:
            return []
            
        description = db.scalar(vuln.description) if vuln.description else ""
        mappings = risk_engine.map_to_mitre_techniques(
            description,
            threshold=threshold
        )
        
        # Update vulnerability with new mappings
        technique_ids = [m["technique_id"] for m in mappings]
        techniques = db.query(MITRETechnique).filter(
            MITRETechnique.technique_id.in_(technique_ids)
        ).all()
        
        vuln.mitre_techniques = techniques
        db.commit()
        
        return mappings
        
    except Exception as e:
        logger.error(f"Error mapping to MITRE ATT&CK: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to map to MITRE ATT&CK"
        )

@router.get("/analysis/{vuln_id}")
@limiter.limit("20/minute")
async def get_comprehensive_analysis(
    request: Request,
    vuln_id: int,
    refresh: bool = False,
    db: Session = Depends(get_db),
    current_user_id: str = Depends(get_current_user_id)
):
    """Get comprehensive vulnerability analysis including risk, MITRE mapping, and threat intel."""
    try:
        vuln = db.query(VulnerabilityData).filter(
            VulnerabilityData.id == vuln_id
        ).first()
        
        if not vuln:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Vulnerability not found"
            )
            
        analysis = await risk_engine.analyze_vulnerability(vuln)
        return analysis
        
    except Exception as e:
        logger.error(f"Error performing vulnerability analysis: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to analyze vulnerability"
        )

@router.websocket("/ws/analysis/{vuln_id}")
async def websocket_analysis_updates(
    websocket: WebSocket,
    vuln_id: int,
    db: Session = Depends(get_db)
):
    """WebSocket endpoint for real-time vulnerability analysis updates."""
    await websocket.accept()
    
    try:
        vuln = db.query(VulnerabilityData).filter(
            VulnerabilityData.id == vuln_id
        ).first()
        
        if not vuln:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
            
        # Initial analysis
        analysis = await risk_engine.analyze_vulnerability(vuln)
        await websocket.send_json(analysis)
        
        # Keep connection alive and send updates
        while True:
            try:
                # Wait for ping (client should send periodic pings)
                data = await websocket.receive_text()
                if data == "ping":
                    await websocket.send_text("pong")
                    continue
                    
                # Recalculate analysis on request
                if data == "refresh":
                    analysis = risk_engine.analyze_vulnerability(vuln)
                    await websocket.send_json(analysis)
                    
            except Exception as e:
                logger.error(f"WebSocket error: {str(e)}")
                break
                
    except Exception as e:
        logger.error(f"Error in analysis WebSocket: {str(e)}")
    finally:
        await websocket.close()