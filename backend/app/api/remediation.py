from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Optional
from fastapi.responses import StreamingResponse
import io

router = APIRouter()

class Vulnerability(BaseModel):
    id: str
    package: str
    ecosystem: str
    severity: Optional[float] = None  # CVSS Score

class RemediationResult(Vulnerability):
    risk_level: str
    fix_command: Optional[str] = None
    fixable: bool = False

def classify_risk(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    elif score >= 7.0:
        return "High"
    elif score >= 4.0:
        return "Medium"
    else:
        return "Low"

def generate_fix_command(ecosystem: str, package: str) -> Optional[str]:
    commands = {
        "PyPI": f"pip install --upgrade {package}",
        "npm": f"npm update {package}",
        "Go": f"go get -u {package}",
        "Maven": f"# Manually update version for {package} in pom.xml",
        "RubyGems": f"gem update {package}",
        "crates.io": f"cargo update -p {package}",
    }
    return commands.get(ecosystem)

@router.post("/remediate", response_model=List[RemediationResult])
def remediate_vulnerabilities(vulns: List[Vulnerability]):
    try:
        results = []
        for vuln in vulns:
            severity = vuln.severity if vuln.severity is not None else 0.0
            risk = classify_risk(severity)
            fix_cmd = generate_fix_command(vuln.ecosystem, vuln.package)

            results.append(
                RemediationResult(
                    **vuln.dict(),
                    risk_level=risk,
                    fix_command=fix_cmd,
                    fixable=bool(fix_cmd)
                )
            )
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Remediation failed: {str(e)}")

@router.post("/remediate/export")
def export_remediation_script(vulns: List[Vulnerability]):
    try:
        output = io.StringIO()
        output.write("#!/bin/bash\n\n")
        output.write("echo 'Starting remediation fixes...'\n\n")

        for vuln in vulns:
            cmd = generate_fix_command(vuln.ecosystem, vuln.package)
            if cmd:
                output.write(f"echo 'Fixing {vuln.package} ({vuln.ecosystem})...'\n")
                output.write(f"{cmd}\n\n")

        output.write("echo 'Remediation complete.'\n")
        output.seek(0)

        return StreamingResponse(
            iter([output.read()]),
            media_type="text/x-sh",
            headers={"Content-Disposition": "attachment; filename=remediate.sh"}
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Export failed: {str(e)}")
