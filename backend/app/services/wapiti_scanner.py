import asyncio
import json
import logging
import tempfile
import os
import platform
from typing import List
from app.core.config import settings
from app.models.scan_models import Vulnerability, ScanRequest
from datetime import datetime

logger = logging.getLogger(__name__)

class WapitiScanner:
    def __init__(self):
        self.binary = settings.WAPITI_BINARY_PATH
        self.is_win = platform.system() == "Windows"

    async def scan(self, target: str, req: ScanRequest) -> List[Vulnerability]:
        """Run Wapiti scan against the target URL."""
        try:
            with tempfile.TemporaryDirectory() as td:
                output = os.path.join(td, "results.json")
                cmd = [
                    self.binary,
                    "-u", target,
                    "-f", "json",
                    "-o", output,
                    "--level", "2",
                    "--timeout", "30"
                ]
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    shell=False
                )
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=settings.SCAN_TIMEOUT)
                if proc.returncode not in (0,1):
                    logger.error(f"Wapiti error: {stderr.decode()}")
                    return []
                # Parse JSON
                raw = json.load(open(output, "r", encoding="utf-8"))
                vulns = []
                for category, items in raw.get("vulnerabilities", {}).items():
                    for itm in items:
                        vulns.append(Vulnerability(
                            id=f"wapiti-{category}-{hash(itm.get('url',''))}",
                            name=f"{category}: {itm.get('method','')}",
                            description=itm.get("info",""),
                            severity="High" if "SQL" in category or "XSS" in category else "Medium",
                            confidence="Medium",
                            solution=itm.get("solution",""),
                            references=itm.get("references", []),
                            url=itm.get("url"),
                            parameter=itm.get("parameter",""),
                            scanner="Wapiti",
                            discovered_at=datetime.utcnow()
                        ))
                return vulns
        except Exception as e:
            logger.error(f"Wapiti scan error: {e}", exc_info=True)
            return []
