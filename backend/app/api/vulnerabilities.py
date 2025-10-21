from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
from typing import List, Optional
from datetime import datetime
from app.database import get_db
from app.models.vulnerability_models import VulnerabilityData, VulnerabilityMitigation
from app.models.asset_models import DiscoveredAsset
from app.services.processors.vulnerability_processor import VulnerabilityProcessor
from sqlalchemy import and_, or_, desc
from pydantic import BaseModel, Field, validator
from app.core.security import get_current_user_id
from app.core.rate_limiter import limiter
from app.core.exceptions import (
    ValidationException,
    DatabaseException,
    ResourceNotFoundException
)
from typing import Dict
import logging

logger = logging.getLogger(__name__)
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

@router.post("/", response_model=VulnerabilityResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("30/minute")
async def create_vulnerability(
    request: Request,
    vulnerability: VulnerabilityCreate,
    db: Session = Depends(get_db),
    current_user_id: str = Depends(get_current_user_id)
):
    """
    Create a new vulnerability record with validation and duplicate checking.
    
    Args:
        request: FastAPI request object for rate limiting
        vulnerability: Vulnerability data from request body
        db: Database session
        current_user_id: Authenticated user ID
        
    Returns:
        VulnerabilityResponse: Created vulnerability record
        
    Raises:
        ValidationException: If validation fails
        ResourceNotFoundException: If asset not found
        DatabaseException: If database operation fails
    """
    try:
        # Validate asset exists and belongs to user
        asset = db.query(DiscoveredAsset).filter(DiscoveredAsset.id == vulnerability.asset_id).first()
        if not asset:
            raise ResourceNotFoundException(f"Asset {vulnerability.asset_id} not found")
        
        # Check for duplicates
        existing = db.query(VulnerabilityData).filter(
            and_(
                VulnerabilityData.asset_id == vulnerability.asset_id,
                VulnerabilityData.title == vulnerability.title,
                VulnerabilityData.source == vulnerability.source
            )
        ).first()
        if existing:
            raise ValidationException("Duplicate vulnerability detected for this asset")
        
        # Process vulnerability data
        processor = VulnerabilityProcessor(db)
        vuln_data = vulnerability.dict()
        
        # Add audit fields
        vuln_data["created_by"] = current_user_id
        vuln_data["updated_by"] = current_user_id
        
        result = await processor.process_vulnerability(vuln_data, vulnerability.asset_id)
        logger.info(f"Created vulnerability for asset {vulnerability.asset_id} by user {current_user_id}")
        return result
        
    except ValidationException as ve:
        logger.warning(f"Validation error in create_vulnerability: {str(ve)}")
        raise
    except ResourceNotFoundException as nf:
        logger.warning(f"Resource not found in create_vulnerability: {str(nf)}")
        raise
    except DatabaseException as de:
        logger.error(f"Database error in create_vulnerability: {str(de)}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error in create_vulnerability: {str(e)}")
        raise DatabaseException("Failed to create vulnerability record")

class PaginatedVulnerabilityResponse(BaseModel):
    items: List[VulnerabilityResponse]
    total: int
    page: int
    size: int
    pages: int

@router.get("/", response_model=PaginatedVulnerabilityResponse)
@limiter.limit("60/minute")
async def list_vulnerabilities(
    request: Request,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=100),
    severity_min: Optional[float] = Query(None, ge=0.0, le=10.0),
    severity_max: Optional[float] = Query(None, ge=0.0, le=10.0),
    asset_id: Optional[int] = None,
    status: Optional[str] = Query(None, regex="^(open|in_progress|resolved|false_positive)$"),
    search: Optional[str] = Query(None, min_length=3, max_length=100),
    sort_by: Optional[str] = Query(None, regex="^(severity|created_at|updated_at)$"),
    sort_desc: bool = True,
    from_date: Optional[datetime] = None,
    to_date: Optional[datetime] = None,
    db: Session = Depends(get_db),
    current_user_id: str = Depends(get_current_user_id)
):
    try:
        query = db.query(VulnerabilityData).join(DiscoveredAsset)
    
        # Apply filters with validation
        if severity_min is not None and severity_max is not None and severity_min > severity_max:
            raise ValidationException("Minimum severity cannot be greater than maximum severity")
    
        if severity_min is not None:
            query = query.filter(VulnerabilityData.severity >= severity_min)
        if severity_max is not None:
            query = query.filter(VulnerabilityData.severity <= severity_max)
        if asset_id is not None:
            # Verify asset exists and belongs to user
            asset = db.query(DiscoveredAsset).filter(DiscoveredAsset.id == asset_id).first()
            if not asset:
                raise ResourceNotFoundException(f"Asset {asset_id} not found")
            query = query.filter(VulnerabilityData.asset_id == asset_id)
        if status:
            query = query.filter(VulnerabilityData.status == status)
        if from_date and to_date and from_date > to_date:
            raise ValidationException("Start date cannot be after end date")
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
    
        # Apply sorting with validation
        if sort_by:
            try:
                sort_column = getattr(VulnerabilityData, sort_by)
                if sort_desc:
                    sort_column = desc(sort_column)
                query = query.order_by(sort_column)
            except AttributeError:
                raise ValidationException(f"Invalid sort column: {sort_by}")
    
        # Get total count with error handling
        try:
            total = query.count()
        except SQLAlchemyError as e:
            logger.error(f"Error counting vulnerabilities: {str(e)}")
            raise DatabaseException("Failed to count vulnerabilities")
    
        # Get paginated results with error handling
        try:
            vulnerabilities = query.offset(skip).limit(limit).all()
        except SQLAlchemyError as e:
            logger.error(f"Error fetching vulnerabilities: {str(e)}")
            raise DatabaseException("Failed to fetch vulnerabilities")
    
        # Calculate pagination metadata
        page = skip // limit + 1
        pages = (total + limit - 1) // limit
    
        logger.info(f"Retrieved {len(vulnerabilities)} vulnerabilities for user {current_user_id}")
        
        return {
            "items": vulnerabilities,
            "total": total,
            "page": page,
            "size": limit,
            "pages": pages
        }
        
    except ValidationException as ve:
        logger.warning(f"Validation error in list_vulnerabilities: {str(ve)}")
        raise
    except ResourceNotFoundException as nf:
        logger.warning(f"Resource not found in list_vulnerabilities: {str(nf)}")
        raise
    except DatabaseException as de:
        logger.error(f"Database error in list_vulnerabilities: {str(de)}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error in list_vulnerabilities: {str(e)}")
        raise DatabaseException("Failed to retrieve vulnerabilities")

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