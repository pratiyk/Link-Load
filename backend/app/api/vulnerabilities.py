from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime
from app.database import get_db
from app.models.vulnerability_models import VulnerabilityData, VulnerabilityMitigation
from app.models.asset_models import DiscoveredAsset
from app.services.processors.vulnerability_processor import VulnerabilityProcessor
from sqlalchemy import and_, or_, desc
from pydantic import BaseModel, Field, validator
from app.core.security import get_current_user_id
from typing import Dict
import logging

router = APIRouter(prefix="/api/v1/vulnerabilities", tags=["vulnerabilities"])
logger = logging.getLogger(__name__)

class VulnerabilityCreate(BaseModel):
    source: str
    title: str
    description: Optional[str] = None
    severity: float = Field(..., ge=0.0, le=10.0)
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    cvss_vector: Optional[str] = None
    cve_ids: Optional[List[str]] = Field(default_factory=list)
    references: Optional[List[str]] = Field(default_factory=list)
    status: str = Field(default="open", pattern="^(open|in_progress|resolved|false_positive)$")
    raw_data: Optional[dict] = None
    asset_id: int

    @validator('severity')
    def validate_severity(cls, v):
        if not 0.0 <= v <= 10.0:
            raise ValueError('Severity must be between 0 and 10')
        return v

class VulnerabilityResponse(BaseModel):
    id: int
    source: str
    title: str
    description: Optional[str]
    severity: float
    cvss_score: Optional[float]
    cvss_vector: Optional[str]
    cve_ids: Optional[List[str]]
    references: Optional[List[str]]
    status: str
    created_at: datetime
    updated_at: datetime
    asset_id: int
    asset_identifier: Optional[str]
    mitigations: Optional[List[dict]]
    raw_data: Optional[dict]

    class Config:
        orm_mode = True

@router.post("/", response_model=VulnerabilityResponse)
async def create_vulnerability(
    vulnerability: VulnerabilityCreate,
    db: Session = Depends(get_db),
    current_user_id: str = Depends(get_current_user_id)
):
    # Validate asset exists
    asset = db.query(DiscoveredAsset).filter(DiscoveredAsset.id == vulnerability.asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    
    # Check for duplicates
    existing = db.query(VulnerabilityData).filter(
        and_(
            VulnerabilityData.asset_id == vulnerability.asset_id,
            VulnerabilityData.title == vulnerability.title,
            VulnerabilityData.source == vulnerability.source
        )
    ).first()
    if existing:
        raise HTTPException(status_code=409, detail="Duplicate vulnerability")
    
    processor = VulnerabilityProcessor(db)
    try:
        vuln_data = vulnerability.dict()
        result = await processor.process_vulnerability(vuln_data, vulnerability.asset_id)
        return result
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        logger.error(f"Error creating vulnerability: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

class PaginatedVulnerabilityResponse(BaseModel):
    items: List[VulnerabilityResponse]
    total: int
    page: int
    size: int
    pages: int

@router.get("/", response_model=PaginatedVulnerabilityResponse)
async def list_vulnerabilities(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=100),
    severity_min: Optional[float] = None,
    severity_max: Optional[float] = None,
    asset_id: Optional[int] = None,
    status: Optional[str] = None,
    search: Optional[str] = None,
    sort_by: Optional[str] = Query(None, regex="^(severity|created_at|updated_at)$"),
    sort_desc: bool = True,
    from_date: Optional[datetime] = None,
    to_date: Optional[datetime] = None,
    db: Session = Depends(get_db),
    current_user_id: str = Depends(get_current_user_id)
):
    query = db.query(VulnerabilityData).join(DiscoveredAsset)
    
    # Apply filters
    if severity_min is not None:
        query = query.filter(VulnerabilityData.severity >= severity_min)
    if severity_max is not None:
        query = query.filter(VulnerabilityData.severity <= severity_max)
    if asset_id is not None:
        query = query.filter(VulnerabilityData.asset_id == asset_id)
    if status:
        query = query.filter(VulnerabilityData.status == status)
    if from_date:
        query = query.filter(VulnerabilityData.created_at >= from_date)
    if to_date:
        query = query.filter(VulnerabilityData.created_at <= to_date)
    if search:
        search_filter = or_(
            VulnerabilityData.title.ilike(f"%{search}%"),
            VulnerabilityData.description.ilike(f"%{search}%"),
            DiscoveredAsset.identifier.ilike(f"%{search}%")
        )
        query = query.filter(search_filter)
    
    # Apply sorting
    if sort_by:
        sort_column = getattr(VulnerabilityData, sort_by)
        if sort_desc:
            sort_column = desc(sort_column)
        query = query.order_by(sort_column)
    
    # Get total count
    total = query.count()
    
    # Get paginated results
    vulnerabilities = query.offset(skip).limit(limit).all()
    
    # Calculate pagination metadata
    page = skip // limit + 1
    pages = (total + limit - 1) // limit
    
    return {
        "items": vulnerabilities,
        "total": total,
        "page": page,
        "size": limit,
        "pages": pages
    }

@router.get("/{vuln_id}", response_model=VulnerabilityResponse)
async def get_vulnerability(
    vuln_id: int,
    db: Session = Depends(get_db),
    current_user_id: str = Depends(get_current_user_id)
):
    vulnerability = db.query(VulnerabilityData).filter(VulnerabilityData.id == vuln_id).first()
    if not vulnerability:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return vulnerability