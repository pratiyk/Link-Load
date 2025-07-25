import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

def setup_logger(name: str, log_file: str = None, level: str = "INFO") -> logging.Logger:
    """
    Set up a logger with both file and console handlers
    """
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper()))
    
    # Prevent duplicate logs if logger already configured
    if logger.handlers:
        return logger
    
    # Create formatters
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # File handler (if specified)
    if log_file:
        # Create logs directory if it doesn't exist
        log_path = Path("logs")
        log_path.mkdir(exist_ok=True)
        
        file_handler = RotatingFileHandler(
            log_path / log_file,
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    return logger

# Create module-specific loggers
attack_surface_logger = setup_logger("attack_surface", "attack_surface.log")
subdomain_logger = setup_logger("subdomain_discovery", "subdomain_discovery.log")
port_scan_logger = setup_logger("port_scanning", "port_scanning.log")
