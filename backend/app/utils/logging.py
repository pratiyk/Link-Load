import logging
import sys
from pathlib import Path

# Create logs directory if it doesn't exist
log_dir = Path("logs")
log_dir.mkdir(exist_ok=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_dir / "attack_surface.log"),
        logging.StreamHandler(sys.stdout)
    ]
)

# Create specific loggers
attack_surface_logger = logging.getLogger("attack_surface")
subdomain_logger = logging.getLogger("subdomain_discovery")
port_scanner_logger = logging.getLogger("port_scanner")
