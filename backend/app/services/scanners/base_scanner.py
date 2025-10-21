from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from datetime import datetime

class BaseScanner(ABC):
    """Base class for all vulnerability scanners"""
    
    def __init__(self):
        self.scan_id: Optional[str] = None
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None

    @abstractmethod
    async def initialize(self) -> bool:
        """Initialize the scanner and verify it's ready to use"""
        pass

    @abstractmethod
    async def start_scan(self, target: str, options: Dict[str, Any]) -> str:
        """Start a new scan and return scan ID"""
        pass

    @abstractmethod
    async def get_scan_status(self, scan_id: str) -> str:
        """Get the current status of a scan"""
        pass

    @abstractmethod
    async def get_scan_results(self, scan_id: str) -> List[Dict[str, Any]]:
        """Get the results of a completed scan"""
        pass

    @abstractmethod
    async def normalize_results(self, raw_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Convert scanner-specific results to normalized format"""
        pass

    async def cleanup(self) -> None:
        """Clean up any resources after scan completion"""
        pass

    def get_scan_duration(self) -> Optional[float]:
        """Get scan duration in seconds"""
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return None