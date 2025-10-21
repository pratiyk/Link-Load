from abc import ABC, abstractmethod
from typing import Dict, Any, Optional

class BaseIntelligence(ABC):
    """Base class for threat intelligence sources"""
    
    def __init__(self):
        self.name: str = self.__class__.__name__

    @abstractmethod
    async def initialize(self) -> bool:
        """Initialize the intelligence source"""
        pass

    @abstractmethod
    async def get_intel(self, title: str, description: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Get threat intelligence data for a vulnerability"""
        pass

    @abstractmethod
    async def update_feed(self) -> bool:
        """Update the threat intelligence feed"""
        pass

    async def cleanup(self) -> None:
        """Clean up any resources"""
        pass