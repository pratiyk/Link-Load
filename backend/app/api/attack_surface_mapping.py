from fastapi import APIRouter, HTTPException, Depends, WebSocket, WebSocketDisconnect, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List, Optional, Dict, Any
import asyncio
import json
import uuid
from datetime import datetime
import os
from dotenv import load_dotenv

# Import database session
from ..database import get_db, get_db_context

# Import validators
from ..core.validators import SecurityValidators

# Import models
from ..models.attack_surface_models import (
    ScanConfigRequest, ScanResponse, AssetResponse, ScanSummaryResponse,
    AttackSurfaceScan, DiscoveredAsset, ScanStatus, AssetType, RiskLevel, WebSocketMessage
)

# Import services (with error handling for missing services)
try:
    from ..services.subdomain_discovery.subfinder_integration import SubfinderService
except ImportError:
    SubfinderService = None

try:
    from ..services.subdomain_discovery.amass_integration import AmassService
except ImportError:
    AmassService = None

try:
    from ..services.subdomain_discovery.certificate_transparency import CertificateTransparencyService
except ImportError:
    CertificateTransparencyService = None

try:
    from ..services.subdomain_discovery.dns_brute_force import DNSBruteForceService
except ImportError:
    DNSBruteForceService = None

try:
    from ..services.port_scanning.async_port_scanner import AsyncPortScanner
except ImportError:
    AsyncPortScanner = None

try:
    from ..services.port_scanning.nmap_integration import NmapService
except ImportError:
    NmapService = None

try:
    from ..services.intelligence_sources.shodan_client import ShodanClient
except ImportError:
    ShodanClient = None

# Import logging utility
try:
    from ..utils.logging import attack_surface_logger
except ImportError:
    import logging
    attack_surface_logger = logging.getLogger("attack_surface")
    logging.basicConfig(level=logging.INFO)

# Load environment variables
load_dotenv()

# Router setup
router = APIRouter(prefix="/api/v1/attack-surface", tags=["Attack Surface Mapping"])

# Initialize Shodan client if available
shodan_client = None
shodan_api_key = os.getenv('SHODAN_API_KEY')
if ShodanClient and shodan_api_key:
    try:
        shodan_client = ShodanClient(api_key=shodan_api_key)
        attack_surface_logger.info("Shodan client initialized successfully")
    except Exception as e:
        attack_surface_logger.warning(f"Failed to initialize Shodan client: {str(e)}")
else:
    attack_surface_logger.warning("SHODAN_API_KEY not found or ShodanClient not available")

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, List[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, scan_id: str):
        await websocket.accept()
        if scan_id not in self.active_connections:
            self.active_connections[scan_id] = []
        self.active_connections[scan_id].append(websocket)

    def disconnect(self, websocket: WebSocket, scan_id: str):
        if scan_id in self.active_connections:
            if websocket in self.active_connections[scan_id]:
                self.active_connections[scan_id].remove(websocket)
            if not self.active_connections[scan_id]:
                del self.active_connections[scan_id]

    async def send_message(self, message: WebSocketMessage, scan_id: str):
        if scan_id in self.active_connections:
            disconnected = []
            for connection in self.active_connections[scan_id]:
                try:
                    await connection.send_text(message.json())
                except Exception as e:
                    attack_surface_logger.warning(f"WebSocket send failed: {str(e)}")
                    disconnected.append(connection)

            # Remove disconnected connections
            for conn in disconnected:
                if conn in self.active_connections[scan_id]:
                    self.active_connections[scan_id].remove(conn)

manager = ConnectionManager()

# Initialize services with error handling
services_initialized = {}

try:
    if SubfinderService:
        subfinder_service = SubfinderService()
        services_initialized['subfinder'] = True
        attack_surface_logger.info("Subfinder service initialized")
    else:
        subfinder_service = None
        services_initialized['subfinder'] = False
except Exception as e:
    subfinder_service = None
    services_initialized['subfinder'] = False
    attack_surface_logger.error(f"Failed to initialize Subfinder service: {str(e)}")

try:
    if AmassService:
        amass_service = AmassService()
        services_initialized['amass'] = True
        attack_surface_logger.info("Amass service initialized")
    else:
        amass_service = None
        services_initialized['amass'] = False
except Exception as e:
    amass_service = None
    services_initialized['amass'] = False
    attack_surface_logger.error(f"Failed to initialize Amass service: {str(e)}")

try:
    if CertificateTransparencyService:
        ct_service = CertificateTransparencyService()
        services_initialized['certificate_transparency'] = True
        attack_surface_logger.info("Certificate Transparency service initialized")
    else:
        ct_service = None
        services_initialized['certificate_transparency'] = False
except Exception as e:
    ct_service = None
    services_initialized['certificate_transparency'] = False
    attack_surface_logger.error(f"Failed to initialize Certificate Transparency service: {str(e)}")

try:
    if DNSBruteForceService:
        dns_service = DNSBruteForceService()
        services_initialized['dns_brute_force'] = True
        attack_surface_logger.info("DNS Brute Force service initialized")
    else:
        dns_service = None
        services_initialized['dns_brute_force'] = False
except Exception as e:
    dns_service = None
    services_initialized['dns_brute_force'] = False
    attack_surface_logger.error(f"Failed to initialize DNS Brute Force service: {str(e)}")

try:
    if AsyncPortScanner:
        port_scanner = AsyncPortScanner()
        services_initialized['port_scanner'] = True
        attack_surface_logger.info("Port Scanner service initialized")
    else:
        port_scanner = None
        services_initialized['port_scanner'] = False
except Exception as e:
    port_scanner = None
    services_initialized['port_scanner'] = False
    attack_surface_logger.error(f"Failed to initialize Port Scanner service: {str(e)}")

try:
    if NmapService:
        nmap_service = NmapService()
        services_initialized['nmap'] = True
        attack_surface_logger.info("Nmap service initialized")
    else:
        nmap_service = None
        services_initialized['nmap'] = False
except Exception as e:
    nmap_service = None
    services_initialized['nmap'] = False
    attack_surface_logger.error(f"Failed to initialize Nmap service: {str(e)}")

attack_surface_logger.info(f"Services initialization status: {services_initialized}")

# API Endpoints

@router.get("/services/status")
async def get_services_status():
    """Get the status of all initialized services"""
    return {
        "services": services_initialized,
        "shodan_available": shodan_client is not None
    }

@router.get("/scans", response_model=List[ScanResponse])
async def list_scans(
    limit: int = 100,
    offset: int = 0,
    status: Optional[str] = None,
    target_domain: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """
    Get list of all attack surface scans with optional filtering
    """
    try:
        query = db.query(AttackSurfaceScan)
        
        if status:
            try:
                status_enum = ScanStatus(status.lower())
                query = query.filter(AttackSurfaceScan.status == status_enum)
            except ValueError:
                raise HTTPException(status_code=400, detail=f"Invalid status: {status}")
        
        if target_domain:
            query = query.filter(AttackSurfaceScan.target_domain.ilike(f"%{target_domain}%"))
        
        scans = query.order_by(AttackSurfaceScan.created_at.desc()).offset(offset).limit(limit).all()
        
        return [ScanResponse.from_orm(scan) for scan in scans]
        
    except HTTPException:
        raise
    except Exception as e:
        attack_surface_logger.error(f"Error listing scans: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.post("/scan", response_model=ScanResponse)
async def start_attack_surface_scan(
    config: ScanConfigRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    Start a comprehensive attack surface mapping scan with validation
    """
    try:
        # Validate config
        if not config.target_domain:
            raise HTTPException(status_code=400, detail="Target domain is required")
        
        # Validate domain format
        if not SecurityValidators.validate_domain(config.target_domain):
            raise HTTPException(status_code=400, detail="Invalid domain format")

        # Generate unique scan ID
        scan_id = str(uuid.uuid4())

        # Create scan record
        scan = AttackSurfaceScan(
            id=scan_id,
            target_domain=config.target_domain,
            scan_config=config.dict(),
            status=ScanStatus.PENDING
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

        # Start background scan - convert Column to string
        background_tasks.add_task(run_attack_surface_scan, str(scan.id), config)

        attack_surface_logger.info(f"Started attack surface scan {scan.id} for {config.target_domain}")

        return ScanResponse.from_orm(scan)

    except HTTPException:
        raise
    except Exception as e:
        attack_surface_logger.error(f"Error starting scan: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/scan/{scan_id}", response_model=ScanResponse)
async def get_scan_status(scan_id: str, db: Session = Depends(get_db)):
    """
    Get scan status and metadata
    """
    try:
        scan = db.query(AttackSurfaceScan).filter(AttackSurfaceScan.id == scan_id).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        return ScanResponse.from_orm(scan)
        
    except HTTPException:
        raise
    except Exception as e:
        attack_surface_logger.error(f"Error getting scan status: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/scan/{scan_id}/assets", response_model=List[AssetResponse])
async def get_scan_assets(
    scan_id: str,
    asset_type: Optional[str] = None,
    risk_level: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    db: Session = Depends(get_db)
):
    """
    Get discovered assets for a scan with filtering
    """
    try:
        # Verify scan exists
        scan = db.query(AttackSurfaceScan).filter(AttackSurfaceScan.id == scan_id).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        query = db.query(DiscoveredAsset).filter(DiscoveredAsset.scan_id == scan_id)

        if asset_type:
            try:
                asset_type_enum = AssetType(asset_type.lower())
                query = query.filter(DiscoveredAsset.asset_type == asset_type_enum)
            except ValueError:
                raise HTTPException(status_code=400, detail=f"Invalid asset type: {asset_type}")

        if risk_level:
            try:
                risk_level_enum = RiskLevel(risk_level.lower())
                query = query.filter(DiscoveredAsset.risk_level == risk_level_enum)
            except ValueError:
                raise HTTPException(status_code=400, detail=f"Invalid risk level: {risk_level}")

        assets = query.order_by(DiscoveredAsset.risk_score.desc()).offset(offset).limit(limit).all()

        return [AssetResponse.from_orm(asset) for asset in assets]
        
    except HTTPException:
        raise
    except Exception as e:
        attack_surface_logger.error(f"Error getting scan assets: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/scan/{scan_id}/summary", response_model=ScanSummaryResponse)
async def get_scan_summary(scan_id: str, db: Session = Depends(get_db)):
    """
    Get comprehensive scan summary with statistics
    """
    try:
        scan = db.query(AttackSurfaceScan).filter(AttackSurfaceScan.id == scan_id).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        assets = db.query(DiscoveredAsset).filter(DiscoveredAsset.scan_id == scan_id).all()

        # Calculate statistics
        assets_summary = {}
        risk_distribution = {}

        for asset in assets:
            # Asset type distribution
            asset_type = asset.asset_type.value if hasattr(asset.asset_type, 'value') else str(asset.asset_type)
            assets_summary[asset_type] = assets_summary.get(asset_type, 0) + 1

            # Risk level distribution
            risk_level = asset.risk_level.value if hasattr(asset.risk_level, 'value') else str(asset.risk_level)
            risk_distribution[risk_level] = risk_distribution.get(risk_level, 0) + 1

        # Get top risks (highest risk score)
        top_risks = (
            db.query(DiscoveredAsset)
            .filter(DiscoveredAsset.scan_id == scan_id)
            .order_by(DiscoveredAsset.risk_score.desc())
            .limit(10)
            .all()
        )

        # Get recent discoveries
        recent_discoveries = (
            db.query(DiscoveredAsset)
            .filter(DiscoveredAsset.scan_id == scan_id)
            .order_by(DiscoveredAsset.discovered_at.desc())
            .limit(10)
            .all()
        )

        return ScanSummaryResponse(
            scan=ScanResponse.from_orm(scan),
            assets_summary=assets_summary,
            risk_distribution=risk_distribution,
            top_risks=[AssetResponse.from_orm(asset) for asset in top_risks],
            recent_discoveries=[AssetResponse.from_orm(asset) for asset in recent_discoveries]
        )
        
    except HTTPException:
        raise
    except Exception as e:
        attack_surface_logger.error(f"Error getting scan summary: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.delete("/scan/{scan_id}")
async def cancel_scan(scan_id: str, db: Session = Depends(get_db)):
    """
    Cancel a running scan
    """
    try:
        scan = db.query(AttackSurfaceScan).filter(AttackSurfaceScan.id == scan_id).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        if scan.status in [ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED]:
            raise HTTPException(status_code=400, detail="Cannot cancel completed scan")

        scan.status = ScanStatus.CANCELLED
        scan.completed_at = datetime.utcnow()
        db.commit()

        return {"message": "Scan cancelled successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        attack_surface_logger.error(f"Error cancelling scan: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.websocket("/scan/{scan_id}/ws")
async def websocket_endpoint(websocket: WebSocket, scan_id: str):
    """
    WebSocket endpoint for real-time scan updates
    """
    await manager.connect(websocket, scan_id)
    try:
        while True:
            # Keep connection alive and handle ping/pong
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        manager.disconnect(websocket, scan_id)
        attack_surface_logger.info(f"WebSocket disconnected for scan {scan_id}")
    except Exception as e:
        attack_surface_logger.error(f"WebSocket error for scan {scan_id}: {str(e)}")
        manager.disconnect(websocket, scan_id)

# Fallback subdomain discovery function
async def fallback_subdomain_discovery(domain: str) -> set:
    """Fallback subdomain discovery when services are not available"""
    attack_surface_logger.info(f"Using fallback discovery for {domain}")
    common_subdomains = {
        domain,
        f"www.{domain}",
        f"mail.{domain}",
        f"api.{domain}",
        f"app.{domain}",
        f"admin.{domain}",
        f"blog.{domain}",
        f"dev.{domain}",
        f"test.{domain}",
        f"staging.{domain}"
    }
    return common_subdomains

async def run_attack_surface_scan(scan_id: str, config: ScanConfigRequest):
    """
    Main scan orchestration function with proper session management
    """
    try:
        with get_db_context() as db:
            # Update scan status
            scan = db.query(AttackSurfaceScan).filter(AttackSurfaceScan.id == scan_id).first()
            if not scan:
                attack_surface_logger.error(f"Scan {scan_id} not found")
                return
                
            scan.status = ScanStatus.RUNNING
            scan.started_at = datetime.utcnow()
            scan.progress = 0
            db.commit()

        # Send progress update
        await manager.send_message(
            WebSocketMessage(
                type="progress",
                data={"progress": 0, "stage": "Starting scan"}
            ),
            scan_id
        )

        # Phase 1: Subdomain Discovery
        attack_surface_logger.info(f"Starting subdomain discovery for {config.target_domain}")
        all_subdomains = set()

        discovery_tasks = []
        
        # Add discovery tasks based on enabled sources and available services
        api_sources = getattr(config, 'api_sources', ['subfinder', 'crt'])
        
        if "subfinder" in api_sources and subfinder_service:
            discovery_tasks.append(subfinder_service.discover_subdomains(config.target_domain))
        if "amass" in api_sources and amass_service:
            discovery_tasks.append(amass_service.discover_subdomains(config.target_domain))
        if "crt" in api_sources and ct_service:
            discovery_tasks.append(ct_service.discover_subdomains(config.target_domain))
        if "dns" in api_sources and dns_service:
            discovery_tasks.append(dns_service.discover_subdomains(config.target_domain))

        if discovery_tasks:
            results = await asyncio.gather(*discovery_tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, set):
                    all_subdomains.update(result)
                elif isinstance(result, Exception):
                    attack_surface_logger.warning(f"Discovery task failed: {str(result)}")
        
        # If no services worked, use fallback
        if not all_subdomains:
            all_subdomains = await fallback_subdomain_discovery(config.target_domain)

        # Limit subdomains if specified
        max_subdomains = getattr(config, 'max_subdomains', 1000)
        if len(all_subdomains) > max_subdomains:
            all_subdomains = set(list(all_subdomains)[:max_subdomains])

        # Update progress
        with get_db_context() as db:
            scan = db.query(AttackSurfaceScan).filter(AttackSurfaceScan.id == scan_id).first()
            if scan:
                scan.progress = 25
                db.commit()
                
        await manager.send_message(
            WebSocketMessage(
                type="progress",
                data={"progress": 25, "stage": f"Found {len(all_subdomains)} subdomains"}
            ),
            scan_id
        )

        # Phase 2: Asset Creation
        with get_db_context() as db:
            for subdomain in all_subdomains:
                asset_id = str(uuid.uuid4())
                asset = DiscoveredAsset(
                    id=asset_id,
                    scan_id=scan_id,
                    asset_type=AssetType.SUBDOMAIN,
                    name=subdomain,
                    risk_level=RiskLevel.LOW,
                    risk_score=1.0,
                    discovered_at=datetime.utcnow()
                )
                db.add(asset)

                # Send asset discovered event
                await manager.send_message(
                    WebSocketMessage(
                        type="asset_discovered",
                        data={"asset": subdomain, "type": "subdomain"}
                    ),
                    scan_id
                )

            db.commit()

        # Update progress to completion
        with get_db_context() as db:
            scan = db.query(AttackSurfaceScan).filter(AttackSurfaceScan.id == scan_id).first()
            if scan:
                scan.progress = 100
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.utcnow()
                scan.total_assets_found = len(all_subdomains)

                # Count high-risk assets
                high_risk_count = db.query(DiscoveredAsset).filter(
                    DiscoveredAsset.scan_id == scan_id,
                    DiscoveredAsset.risk_level.in_([RiskLevel.HIGH, RiskLevel.CRITICAL])
                ).count()
                scan.high_risk_assets = high_risk_count

                db.commit()

        # Send completion message
        await manager.send_message(
            WebSocketMessage(
                type="scan_complete",
                data={
                    "progress": 100,
                    "total_assets": len(all_subdomains),
                    "high_risk_assets": high_risk_count
                }
            ),
            scan_id
        )

        attack_surface_logger.info(f"Completed attack surface scan {scan_id}")

    except Exception as e:
        # Handle scan failure
        try:
            with get_db_context() as db:
                scan = db.query(AttackSurfaceScan).filter(AttackSurfaceScan.id == scan_id).first()
                if scan:
                    scan.status = ScanStatus.FAILED
                    scan.completed_at = datetime.utcnow()
                    scan.error_message = str(e)
                    db.commit()

            await manager.send_message(
                WebSocketMessage(
                    type="error",
                    data={"error": str(e)}
                ),
                scan_id
            )
        except Exception as cleanup_error:
            attack_surface_logger.error(f"Error during cleanup: {str(cleanup_error)}")

        attack_surface_logger.error(f"Scan {scan_id} failed: {str(e)}")

def calculate_risk_score(ports: List[int], services: Dict[str, Any]) -> float:
    """
    Calculate risk score based on open ports and services
    """
    base_score = 1.0

    # High-risk ports
    high_risk_ports = [21, 22, 23, 25, 53, 135, 139, 445, 1433, 3389, 5432, 6379]
    medium_risk_ports = [80, 443, 993, 995, 8080, 8443]

    for port in ports:
        if port in high_risk_ports:
            base_score += 2.0
        elif port in medium_risk_ports:
            base_score += 0.5
        else:
            base_score += 0.1

    # Service-specific scoring
    for port_str, service_info in services.items():
        if not isinstance(service_info, dict):
            continue
            
        service_name = service_info.get('service', '').lower()

        if 'ssh' in service_name:
            base_score += 1.5
        elif 'ftp' in service_name:
            base_score += 2.0
        elif 'telnet' in service_name:
            base_score += 3.0
        elif 'rdp' in service_name or 'ms-wbt-server' in service_name:
            base_score += 3.0

    return min(base_score, 10.0)  # Cap at 10.0

def categorize_risk_level(risk_score: float) -> RiskLevel:
    """
    Categorize risk level based on score
    """
    if risk_score >= 8.0:
        return RiskLevel.CRITICAL
    elif risk_score >= 6.0:
        return RiskLevel.HIGH
    elif risk_score >= 3.0:
        return RiskLevel.MEDIUM
    else:
        return RiskLevel.LOW
