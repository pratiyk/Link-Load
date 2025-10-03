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

class NucleiScanner:
    def __init__(self):
        self.binary = settings.NUCLEI_BINARY_PATH
        self.is_win = platform.system() == "Windows"

    async def scan(self, target: str, req: ScanRequest) -> List[Vulnerability]:
        """Run Nuclei scan with OWASP tags against target URL."""
        try:
            with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
                output = tf.name
            cmd = [
                self.binary,
                "-u", target,
                "-json",
                "-o", output,
                "-silent",
                "-tags", "owasp,sqli,xss,ssrf,rce,lfi"
            ]
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, shell=False
            )
            await asyncio.wait_for(proc.communicate(), timeout=settings.SCAN_TIMEOUT)
            if os.path.getsize(output) == 0:
                return []
            vulns = []
            with open(output, "r", encoding="utf-8") as f:
                for line in f:
                    data = json.loads(line)
                    info = data.get("info",{})
                    vulns.append(Vulnerability(
                        id=f"nuclei-{data.get('template-id')}-{hash(data.get('matched-at',''))}",
                        name=info.get("name","Unknown"),
                        description=info.get("description",""),
                        severity=info.get("severity","Info").capitalize(),
                        confidence="High",
                        solution=info.get("remediation",""),
                        references=info.get("reference",[]) if isinstance(info.get("reference"), list) else [info.get("reference","")],
                        url=data.get("matched-at"),
                        parameter="",
                        scanner="Nuclei",
                        discovered_at=datetime.utcnow()
                    ))
            try: os.unlink(output)
            except: pass
            return vulns
        except Exception as e:
            logger.error(f"Nuclei scan error: {e}", exc_info=True)
            return []
