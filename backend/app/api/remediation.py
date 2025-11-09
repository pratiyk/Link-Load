from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import List, Optional
from fastapi.responses import StreamingResponse
import io

router = APIRouter(prefix="/remediation", tags=["Remediation"])

class Vulnerability(BaseModel):
    id: str
    package: str
    ecosystem: str
    severity: Optional[float] = None  # CVSS Score

class RemediationResult(Vulnerability):
    risk_level: str
    fix_command: Optional[str] = None
    fixable: bool = False


class RemediationSuggestionRequest(BaseModel):
    title: str
    description: Optional[str] = None
    severity: str = Field(..., description="Severity label (critical/high/medium/low)")
    affected_components: List[str] = Field(default_factory=list)


class RemediationSuggestionResponse(BaseModel):
    summary: str
    steps: List[str]
    commands: List[str]
    priority: str
    references: List[str] = Field(default_factory=list)

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


def _severity_priority(severity: str) -> str:
    mapping = {
        "critical": "immediate",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "informational",
    }
    return mapping.get(severity.lower(), "medium")


def _build_commands(components: List[str]) -> List[str]:
    commands: List[str] = []
    if any("package.json" in comp or "yarn.lock" in comp for comp in components):
        commands.append("npm audit fix")
    if any(comp.endswith("requirements.txt") for comp in components):
        commands.append("pip install -r requirements.txt --upgrade")
    if not commands:
        commands.append("echo 'Review manual remediation steps'")
    return commands


@router.post("/suggest", response_model=RemediationSuggestionResponse)
def suggest_remediation(payload: RemediationSuggestionRequest) -> RemediationSuggestionResponse:
    try:
        priority = _severity_priority(payload.severity)
        components = payload.affected_components or []
        steps = [
            f"Validate findings for: {payload.title}",
            "Review vendor advisories and changelogs",
            "Schedule remediation window with stakeholders",
            "Verify fixes in staging before production rollout",
        ]
        if components:
            steps.insert(1, f"Assess impact on components: {', '.join(components)}")

        commands = _build_commands(components)

        return RemediationSuggestionResponse(
            summary=(payload.description or payload.title),
            steps=steps,
            commands=commands,
            priority=priority,
            references=[
                "https://owasp.org/www-project-top-ten/",
                "https://nvd.nist.gov/general/nvd-dashboard",
            ],
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Remediation suggestion failed: {str(exc)}")

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
