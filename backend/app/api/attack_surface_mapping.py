from fastapi import APIRouter, HTTPException, Depends, WebSocket, WebSocketDisconnect, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List, Optional, Dict, Any
import asyncio
import json
from datetime import datetime
import os
from dotenv import load_dotenv

from ..models.attack_surface_models import (
    ScanConfigRequest, ScanResponse, AssetResponse, ScanSummaryResponse,
    AttackSurfaceScan, DiscoveredAsset, ScanStatus, AssetType, RiskLevel, WebSocketMessage
)
from ..services.subdomain_discovery.subfinder_integration import SubfinderService
from ..services.subdomain_discovery.amass_integration import AmassService
from ..services.subdomain_discovery.certificate_transparency import CertificateTransparencyService
from ..services.subdomain_discovery.dns_brute_force import DNSBruteForceService
from ..services.port_scanning.async_port_scanner import AsyncPortScanner
from ..services.port_scanning.nmap_integration import NmapService
from ..services.intelligence_sources.shodan_client import ShodanClient
from ..utils.logging import attack_surface_logger

router = APIRouter(prefix="/api/v1/attack-surface", tags=["Attack Surface Mapping"])

load_dotenv()

# Placeholder for database session. You need to implement this.
def get_db():
    # In a real application, this would yield a database session
    # For example, using SQLAlchemy's SessionLocal:
    # db = SessionLocal()
    # try:
    #     yield db
    # finally:
    #     db.close()
    raise NotImplementedError("Database dependency 'get_db' not implemented.")

if os.getenv('SHODAN_API_KEY'):
    shodan_client = ShodanClient(api_key=os.getenv('SHODAN_API_KEY'))
    attack_surface_logger.info("Shodan client initialized successfully")
else:
    attack_surface_logger.warning("SHODAN_API_KEY not found in environment variables")

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
            self.active_connections[scan_id].remove(websocket)
            if not self.active_connections[scan_id]:
                del self.active_connections[scan_id]

    async def send_message(self, message: WebSocketMessage, scan_id: str):
        if scan_id in self.active_connections:
            disconnected = []
            for connection in self.active_connections[scan_id]:
                try:
                    await connection.send_text(message.json())
                except:
                    disconnected.append(connection)

            # Remove disconnected connections
            for conn in disconnected:
                self.active_connections[scan_id].remove(conn)

manager = ConnectionManager()

# Initialize services
subfinder_service = SubfinderService()
amass_service = AmassService()
ct_service = CertificateTransparencyService()
dns_service = DNSBruteForceService()
port_scanner = AsyncPortScanner()
nmap_service = NmapService()

# The shodan_client is already initialized conditionally above.
# This line was redundant and hardcoded, hence removed.

@router.post("/scan", response_model=ScanResponse)
async def start_attack_surface_scan(
    config: ScanConfigRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    Start a comprehensive attack surface mapping scan
    """
    try:
        # Create scan record
        scan = AttackSurfaceScan(
            target_domain=config.target_domain,
            scan_config=config.dict()
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

        # Start background scan
        background_tasks.add_task(run_attack_surface_scan, scan.id, config)

        attack_surface_logger.info(f"Started attack surface scan {scan.id} for {config.target_domain}")

        return ScanResponse.from_orm(scan)

    except Exception as e:
        attack_surface_logger.error(f"Error starting scan: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/scan/{scan_id}", response_model=ScanResponse)
async def get_scan_status(scan_id: str, db: Session = Depends(get_db)):
    """
    Get scan status and metadata
    """
    scan = db.query(AttackSurfaceScan).filter(AttackSurfaceScan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return ScanResponse.from_orm(scan)

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
    query = db.query(DiscoveredAsset).filter(DiscoveredAsset.scan_id == scan_id)

    if asset_type:
        query = query.filter(DiscoveredAsset.asset_type == asset_type)

    if risk_level:
        query = query.filter(DiscoveredAsset.risk_level == risk_level)

    assets = query.offset(offset).limit(limit).all()

    return [AssetResponse.from_orm(asset) for asset in assets]

@router.get("/scan/{scan_id}/summary", response_model=ScanSummaryResponse)
async def get_scan_summary(scan_id: str, db: Session = Depends(get_db)):
    """
    Get comprehensive scan summary with statistics
    """
    scan = db.query(AttackSurfaceScan).filter(AttackSurfaceScan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    assets = db.query(DiscoveredAsset).filter(DiscoveredAsset.scan_id == scan_id).all()

    # Calculate statistics
    assets_summary = {}
    risk_distribution = {}

    for asset in assets:
        # Asset type distribution
        asset_type = asset.asset_type.value
        assets_summary[asset_type] = assets_summary.get(asset_type, 0) + 1

        # Risk level distribution
        risk_level = asset.risk_level.value
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

@router.delete("/scan/{scan_id}")
async def cancel_scan(scan_id: str, db: Session = Depends(get_db)):
    """
    Cancel a running scan
    """
    scan = db.query(AttackSurfaceScan).filter(AttackSurfaceScan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status in [ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED]:
        raise HTTPException(status_code=400, detail="Cannot cancel completed scan")

    scan.status = ScanStatus.CANCELLED
    scan.completed_at = datetime.utcnow()
    db.commit()

    return {"message": "Scan cancelled successfully"}

@router.websocket("/scan/{scan_id}/ws")
async def websocket_endpoint(websocket: WebSocket, scan_id: str):
    """
    WebSocket endpoint for real-time scan updates
    """
    await manager.connect(websocket, scan_id)
    try:
        while True:
            # Keep connection alive
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket, scan_id)

async def run_attack_surface_scan(scan_id: str, config: ScanConfigRequest):
    """
    Main scan orchestration function
    """
    # This calls the get_db() dependency directly. In a real application,
    # you would set up your database session management appropriately,
    # perhaps using a context manager or dependency injection that handles
    # closing the session.
    db = next(get_db())

    try:
        # Update scan status
        scan = db.query(AttackSurfaceScan).filter(AttackSurfaceScan.id == scan_id).first()
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
        if "subfinder" in config.api_sources:
            discovery_tasks.append(subfinder_service.discover_subdomains(config.target_domain))
        if "amass" in config.api_sources:
            discovery_tasks.append(amass_service.discover_subdomains(config.target_domain))
        if "crt" in config.api_sources:
            discovery_tasks.append(ct_service.discover_subdomains(config.target_domain))
        if "dns" in config.api_sources:
            discovery_tasks.append(dns_service.discover_subdomains(config.target_domain))

        results = await asyncio.gather(*discovery_tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, set):
                all_subdomains.update(result)

        # Limit subdomains if specified
        if len(all_subdomains) > config.max_subdomains:
            all_subdomains = set(list(all_subdomains)[:config.max_subdomains])

        # Update progress
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
        for subdomain in all_subdomains:
            asset = DiscoveredAsset(
                scan_id=scan_id,
                asset_type=AssetType.SUBDOMAIN,
                name=subdomain,
                risk_level=RiskLevel.LOW,
                risk_score=1.0
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

        # Update progress
        scan.progress = 50
        db.commit()
        await manager.send_message(
            WebSocketMessage(
                type="progress",
                data={"progress": 50, "stage": "Starting port scanning"}
            ),
            scan_id
        )

        # Phase 3: Port Scanning (if enabled)
        if config.port_scan_enabled:
            port_list = port_scanner.get_port_list(config.port_range)

            scan_tasks = []
            for subdomain in list(all_subdomains)[:50]:  # Limit concurrent scans
                scan_tasks.append(port_scanner.scan_host(subdomain, port_list))

            scan_results = await asyncio.gather(*scan_tasks, return_exceptions=True)

            for i, result in enumerate(scan_results):
                if hasattr(result, 'open_ports') and result.open_ports:
                    subdomain = list(all_subdomains)[i]

                    # Update asset with port information
                    asset = db.query(DiscoveredAsset).filter(
                        DiscoveredAsset.scan_id == scan_id,
                        DiscoveredAsset.name == subdomain
                    ).first()

                    if asset:
                        asset.ports = result.open_ports
                        asset.services = {
                            str(port): {
                                'service': info.service,
                                'version': info.version,
                                'banner': info.banner
                            }
                            for port, info in result.services.items()
                        }

                        # Calculate risk score based on open ports
                        risk_score = calculate_risk_score(result.open_ports, result.services)
                        asset.risk_score = risk_score
                        asset.risk_level = categorize_risk_level(risk_score)

            db.commit()

        # Update progress
        scan.progress = 75
        db.commit()
        await manager.send_message(
            WebSocketMessage(
                type="progress",
                data={"progress": 75, "stage": "Enriching with threat intelligence"}
            ),
            scan_id
        )

        # Phase 4: Threat Intelligence Enrichment
        # This would integrate with Shodan/BinaryEdge APIs
        # (Implementation depends on API key availability)

        # Final update
        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.utcnow()
        scan.progress = 100
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
        scan = db.query(AttackSurfaceScan).filter(AttackSurfaceScan.id == scan_id).first()
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

        attack_surface_logger.error(f"Scan {scan_id} failed: {str(e)}")

    finally:
        db.close()

def calculate_risk_score(ports: List[int], services: Dict[int, Any]) -> float:
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
    for port, service_info in services.items():
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
