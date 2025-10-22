"""Configuration and settings for intelligence mapping services."""
from pydantic import BaseSettings
from typing import List, Dict, Any, Optional
import os

class IntelligenceMappingSettings(BaseSettings):
    """Settings for intelligence mapping services."""
    
    # MITRE ATT&CK Mapping
    MITRE_SEMANTIC_THRESHOLD: float = 0.75
    MITRE_SYNTACTIC_THRESHOLD: float = 0.60
    MITRE_RULE_THRESHOLD: float = 0.50
    
    # NLP Model Settings
    NLP_MODEL: str = "en_core_web_lg"
    TRANSFORMER_MODEL: str = "microsoft/mpnet-base"
    USE_GPU: bool = True
    
    # Real-time Intelligence
    INTEL_BUFFER_SIZE: int = 1000
    BROADCAST_BATCH_SIZE: int = 100
    MAX_CLIENTS_PER_USER: int = 5
    
    # WebSocket Settings
    WS_HEARTBEAT_INTERVAL: int = 30  # seconds
    WS_CLOSE_TIMEOUT: int = 10  # seconds
    
    # Model Retraining
    MIN_SAMPLES_FOR_RETRAINING: int = 1000
    RETRAINING_INTERVAL_HOURS: int = 24
    
    # Cache Settings
    TECHNIQUE_CACHE_TTL: int = 3600  # 1 hour
    INTEL_CACHE_TTL: int = 300  # 5 minutes
    
    # Performance Tuning
    MAX_CONCURRENT_MAPPINGS: int = 10
    BATCH_SIZE: int = 50
    
    class Config:
        env_prefix = "INTEL_"
        case_sensitive = True

intelligence_settings = IntelligenceMappingSettings()