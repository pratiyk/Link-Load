
import logging
import sys
from pathlib import Path

# Create logs directory if it doesn't exist
log_dir = Path("logs")
log_dir.mkdir(exist_ok=True)

class LevelFilter(logging.Filter):
    def __init__(self, level):
        super().__init__()
        self.level = level
    def filter(self, record):
        return record.levelno == self.level

# Handlers for each log type
info_handler = logging.FileHandler(log_dir / "info.log")
info_handler.setLevel(logging.INFO)
info_handler.addFilter(LevelFilter(logging.INFO))

error_handler = logging.FileHandler(log_dir / "error.log")
error_handler.setLevel(logging.ERROR)
error_handler.addFilter(LevelFilter(logging.ERROR))

# System log handler (for system-level events, e.g., startup/shutdown)
system_handler = logging.FileHandler(log_dir / "system.log")
system_handler.setLevel(logging.INFO)
system_handler.addFilter(logging.Filter("system"))

# Business error log handler (for business logic errors)
business_error_handler = logging.FileHandler(log_dir / "business_error.log")
business_error_handler.setLevel(logging.ERROR)
business_error_handler.addFilter(logging.Filter("business_error"))

console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)

formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
for handler in [info_handler, error_handler, system_handler, business_error_handler, console_handler]:
    handler.setFormatter(formatter)

root_logger = logging.getLogger()
root_logger.setLevel(logging.INFO)
root_logger.handlers = [info_handler, error_handler, system_handler, business_error_handler, console_handler]

# Usage: logger = logging.getLogger("system") for system logs
# Usage: logger = logging.getLogger("business_error") for business error logs
# Usage: logger = logging.getLogger(__name__) for module logs

attack_surface_logger = logging.getLogger("attack_surface")
subdomain_logger = logging.getLogger("subdomain_discovery")
port_scanner_logger = logging.getLogger("port_scanner")
