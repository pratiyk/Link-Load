"""
LLM Integration Service for AI-powered security analysis.

Supports:
- OpenAI GPT-4
- Anthropic Claude
- Groq (Llama/Mixtral)
- Fallback mechanism

Run: Configure GROQ_API_KEY, OPENAI_API_KEY, or ANTHROPIC_API_KEY in .env
"""

import os
import asyncio
from typing import Optional, List, Dict, Any
from abc import ABC, abstractmethod
import logging

from app.core.config import settings

logger = logging.getLogger(__name__)


class LLMProvider(ABC):
    """Base class for LLM providers"""
    
    @abstractmethod
    async def analyze_vulnerabilities(
        self,
        vulnerabilities: List[Dict[str, Any]],
        target_url: str,
        business_context: Optional[str] = None
    ) -> Dict[str, Any]:
        """Analyze vulnerabilities and generate recommendations"""
        pass
    
    @abstractmethod
    async def generate_executive_summary(
        self,
        vulnerabilities: List[Dict[str, Any]],
        risk_score: float,
        risk_level: str,
        threat_intel: Optional[Dict[str, Any]] = None
    ) -> str:
        """Generate executive summary of scan results"""
        pass


class OpenAIProvider(LLMProvider):
    """OpenAI GPT-4 integration"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or settings.OPENAI_API_KEY
        if not self.api_key:
            raise ValueError("OPENAI_API_KEY environment variable not set")
        
        try:
            import openai
            self.client = openai.AsyncOpenAI(api_key=self.api_key)
        except ImportError:
            raise ImportError("openai package not installed. Run: pip install openai")
    
    async def analyze_vulnerabilities(
        self,
        vulnerabilities: List[Dict[str, Any]],
        target_url: str,
        business_context: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Analyze vulnerabilities using GPT-4 with detailed remediation and MITRE mapping
        """
        if not vulnerabilities:
            return {"recommendations": [], "summary": "No vulnerabilities found"}
        
        vuln_summary = self._prepare_vulnerability_summary(vulnerabilities[:10])
        
        prompt = f"""You are a senior penetration tester and security architect analyzing vulnerability scan results.

Target: {target_url}
{f'Business Context: {business_context}' if business_context else ''}

Found Vulnerabilities:
{vuln_summary}

For EACH vulnerability, provide comprehensive analysis:

1. SEVERITY ASSESSMENT (1-10 scale with justification)
2. MITRE ATT&CK MAPPING:
   - Primary Technique ID and Name (e.g., T1190 - Exploit Public-Facing Application)
   - Associated Tactic (e.g., Initial Access, Execution)
   - Sub-techniques if applicable
3. DETAILED REMEDIATION STEPS:
   - Immediate mitigation (what to do RIGHT NOW)
   - Code-level fix (specific code changes or configurations)
   - Infrastructure hardening (WAF rules, network controls)
   - Long-term prevention (architectural changes)
4. EXPLOITATION SCENARIO: How an attacker would exploit this
5. BUSINESS IMPACT: Data breach risk, compliance violations
6. FIX COMPLEXITY: low/medium/high with time estimate
7. DETECTION METHODS: How to detect exploitation attempts

Format as JSON:
{{
    "vulnerabilities": [
        {{
            "title": "...",
            "severity_score": 1-10,
            "severity_justification": "...",
            "mitre_attack": {{
                "technique_id": "T1XXX",
                "technique_name": "...",
                "tactic": "...",
                "sub_techniques": ["T1XXX.XXX"]
            }},
            "remediation": {{
                "immediate": ["step1", "step2"],
                "code_fix": ["specific code/config changes"],
                "infrastructure": ["WAF rules, network controls"],
                "long_term": ["architectural improvements"]
            }},
            "exploitation_scenario": "...",
            "business_impact": "...",
            "fix_complexity": "low|medium|high",
            "estimated_fix_time": "X hours/days",
            "detection_methods": ["log patterns", "alerts"]
        }}
    ],
    "attack_chain_analysis": "How vulnerabilities could be chained",
    "executive_summary": "Overall security posture"
}}"""
        
        try:
            response = await self.client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {
                        "role": "system",
                        "content": "You are an expert penetration tester and security architect. Provide detailed, actionable security analysis with MITRE ATT&CK mappings. Always respond with valid JSON. Be specific about code fixes."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.3,
                max_tokens=4000,
                timeout=45
            )
            
            import json
            result_text = response.choices[0].message.content
            
            try:
                result = json.loads(result_text)
            except json.JSONDecodeError:
                if "```json" in result_text:
                    result_text = result_text.split("```json")[1].split("```")[0]
                    result = json.loads(result_text)
                elif "```" in result_text:
                    result_text = result_text.split("```")[1].split("```")[0]
                    result = json.loads(result_text)
                else:
                    raise
            
            logger.info(f"OpenAI analysis complete for {len(vulnerabilities)} vulnerabilities with MITRE mapping")
            return result
        
        except Exception as e:
            logger.error(f"OpenAI analysis failed: {e}")
            raise
    
    async def generate_executive_summary(
        self,
        vulnerabilities: List[Dict[str, Any]],
        risk_score: float,
        risk_level: str,
        threat_intel: Optional[Dict[str, Any]] = None
    ) -> str:
        """Generate executive summary using GPT-4"""
        
        # Prepare top vulnerabilities for context
        top_vulns = self._prepare_vulnerability_summary(vulnerabilities[:5]) if vulnerabilities else "None detected"
        
        # Prepare threat intel summary
        threat_intel_summary = self._prepare_threat_intel_summary(threat_intel) if threat_intel else "No external threat intelligence collected"
        
        prompt = f"""Analyze this security scan and generate a technical summary for security professionals.

SCAN METRICS:
- Total Vulnerabilities: {len(vulnerabilities)}
- Risk Score: {risk_score:.1f}/10 ({risk_level})
- Critical: {sum(1 for v in vulnerabilities if v.get('severity') == 'critical')}
- High: {sum(1 for v in vulnerabilities if v.get('severity') == 'high')}
- Medium: {sum(1 for v in vulnerabilities if v.get('severity') == 'medium')}
- Low: {sum(1 for v in vulnerabilities if v.get('severity') == 'low')}

TOP FINDINGS:
{top_vulns}

EXTERNAL THREAT INTELLIGENCE:
{threat_intel_summary}

GENERATE A TECHNICAL SUMMARY (4 paragraphs, third person):

1. SECURITY POSTURE & ATTACK SURFACE: Assess the target's security state. Reference specific vulnerability types found (e.g., XSS, SQL injection, misconfigurations). Include external reputation data if available. Mention MITRE ATT&CK techniques that map to findings. Be direct about severity.

2. EXTERNAL THREAT LANDSCAPE: Summarize what external intelligence sources reveal about this target. Include VirusTotal results, AbuseIPDB reputation, Shodan exposure (open ports, services), breach history, and Safe Browsing status. If external intel shows concerning indicators, highlight them with specific data.

3. TECHNICAL RISKS & ATTACK CHAINS: Identify the most critical attack vectors combining scan findings with external intel. Explain how vulnerabilities could be chained (e.g., "Initial access via T1190 could lead to..."). Reference CVE IDs, CWE categories, MITRE technique IDs, or Shodan-detected services.

4. REMEDIATION PRIORITIES & DEFENSIVE MEASURES: Provide specific, actionable remediation steps ordered by priority. Include:
   - Immediate mitigations (within 24-48 hours)
   - Code-level fixes with specific guidance
   - Infrastructure hardening (WAF rules, network segmentation)
   - Detection recommendations (SIEM rules, log monitoring)

RULES:
- Write in third person ("The target application...", "The scan identified...", "Administrators should...")
- Be technical and specific - this is for security professionals
- Reference MITRE ATT&CK technique IDs where applicable (e.g., T1190, T1059.007)
- Integrate external threat intel findings naturally into the narrative
- Do NOT include any headers like "Executive Summary" or "Security Assessment"
- Do NOT use markdown formatting (no **, ##, or bullet points)
- Keep each paragraph 3-5 sentences
- If no vulnerabilities found but external intel shows concerns, focus on those
- If both vulnerabilities and external concerns are minimal, state the target has a strong security posture"""
        
        try:
            response = await self.client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {
                        "role": "system",
                        "content": "You are a senior penetration tester and threat intelligence analyst writing technical security reports. Be concise, technical, and actionable. Always reference MITRE ATT&CK techniques when discussing attack patterns. Never use first person. Never include section headers in your output. Integrate threat intelligence findings naturally."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.4,
                max_tokens=1200,
                timeout=30
            )
            
            return response.choices[0].message.content.strip()
        
        except Exception as e:
            logger.error(f"Executive summary generation failed: {e}")
            raise
    
    def _prepare_threat_intel_summary(self, threat_intel: Dict[str, Any]) -> str:
        """Prepare threat intelligence data for LLM analysis"""
        if not threat_intel:
            return "No external threat intelligence available"
        
        parts = []
        
        # Reputation
        reputation = threat_intel.get("reputation", {})
        if reputation.get("score") is not None:
            parts.append(f"Reputation Score: {reputation.get('score')}/100 ({reputation.get('risk_level', 'Unknown')} risk)")
        
        # VirusTotal
        vt = threat_intel.get("virustotal", {})
        if vt and vt.get("status") != "not_found":
            parts.append(f"VirusTotal: {vt.get('malicious', 0)} malicious, {vt.get('suspicious', 0)} suspicious, {vt.get('harmless', 0)} clean detections")
        
        # Google Safe Browsing
        gsb = threat_intel.get("google_safe_browsing", {})
        if gsb:
            status = "FLAGGED - " + ", ".join(gsb.get("threat_types", [])) if gsb.get("is_flagged") else "Clean"
            parts.append(f"Google Safe Browsing: {status}")
        
        # AbuseIPDB
        abuse = threat_intel.get("abuseipdb", {})
        if abuse and abuse.get("ip_address"):
            parts.append(f"AbuseIPDB: {abuse.get('abuse_confidence_score', 0)}% confidence, {abuse.get('total_reports', 0)} reports, ISP: {abuse.get('isp', 'Unknown')}")
        
        # Shodan
        shodan = threat_intel.get("shodan", {})
        if shodan and shodan.get("ip"):
            parts.append(f"Shodan: {shodan.get('open_ports_count', 0)} open ports, {shodan.get('vuln_count', 0)} known vulnerabilities, Services: {', '.join(shodan.get('services', [])[:5]) or 'None detected'}")
        
        # Breach data
        leak = threat_intel.get("leak_lookup", {})
        if leak:
            if leak.get("has_breaches") or leak.get("breaches_found"):
                parts.append(f"Breach History: {leak.get('breaches_found', 'Multiple')} breaches detected")
            else:
                parts.append("Breach History: No breaches found")
        
        # Risk indicators
        indicators = threat_intel.get("risk_indicators", [])
        if indicators:
            indicator_summary = ", ".join([f"{i.get('type')} ({i.get('severity')})" for i in indicators[:3]])
            parts.append(f"Risk Indicators: {len(indicators)} active - {indicator_summary}")
        
        return "\n".join(parts) if parts else "External intelligence queries returned no significant findings"
    
    def _prepare_vulnerability_summary(self, vulnerabilities: List[Dict]) -> str:
        """Prepare vulnerability data for LLM analysis"""
        summary = ""
        for i, vuln in enumerate(vulnerabilities, 1):
            summary += f"""
{i}. {vuln.get('title', 'Unknown')}
   Severity: {vuln.get('severity', 'Unknown')}
   CVSS: {vuln.get('cvss_score', 'N/A')}
   Location: {vuln.get('location', 'Unknown')}
   Description: {vuln.get('description', 'No description')}
"""
        return summary


class GroqProvider(LLMProvider):
    """Groq AI integration - Fast, free, and powerful"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or settings.GROQ_API_KEY
        if not self.api_key:
            raise ValueError("GROQ_API_KEY environment variable not set")
        
        try:
            from groq import AsyncGroq
            self.client = AsyncGroq(api_key=self.api_key)
        except ImportError:
            raise ImportError("groq package not installed. Run: pip install groq")
    
    async def analyze_vulnerabilities(
        self,
        vulnerabilities: List[Dict[str, Any]],
        target_url: str,
        business_context: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Analyze vulnerabilities using Groq (Llama 3.3) with detailed remediation and MITRE mapping
        """
        if not vulnerabilities:
            return {"recommendations": [], "summary": "No vulnerabilities found"}
        
        vuln_summary = self._prepare_vulnerability_summary(vulnerabilities[:10])
        
        prompt = f"""You are a senior penetration tester and security architect analyzing vulnerability scan results.

Target: {target_url}
{f'Business Context: {business_context}' if business_context else ''}

Found Vulnerabilities:
{vuln_summary}

For EACH vulnerability, provide a comprehensive analysis:

1. SEVERITY ASSESSMENT (1-10 scale with justification)
2. MITRE ATT&CK MAPPING:
   - Primary Technique ID and Name (e.g., T1190 - Exploit Public-Facing Application)
   - Associated Tactic (e.g., Initial Access, Execution, Persistence)
   - Sub-techniques if applicable
3. DETAILED REMEDIATION STEPS (4-6 specific, actionable items):
   - Immediate mitigation (what to do RIGHT NOW)
   - Code-level fix (specific code changes or configurations)
   - Infrastructure hardening (WAF rules, network controls)
   - Long-term prevention (architectural changes)
4. EXPLOITATION SCENARIO: How an attacker would exploit this
5. BUSINESS IMPACT: Data breach risk, compliance violations, operational impact
6. FIX COMPLEXITY: low/medium/high with time estimate
7. DETECTION METHODS: How to detect exploitation attempts

Format as JSON:
{{
    "vulnerabilities": [
        {{
            "title": "...",
            "severity_score": 1-10,
            "severity_justification": "...",
            "mitre_attack": {{
                "technique_id": "T1XXX",
                "technique_name": "...",
                "tactic": "...",
                "sub_techniques": ["T1XXX.XXX"]
            }},
            "remediation": {{
                "immediate": ["step1", "step2"],
                "code_fix": ["specific code/config changes"],
                "infrastructure": ["WAF rules, network controls"],
                "long_term": ["architectural improvements"]
            }},
            "exploitation_scenario": "...",
            "business_impact": "...",
            "fix_complexity": "low|medium|high",
            "estimated_fix_time": "X hours/days",
            "detection_methods": ["log patterns", "alerts"]
        }}
    ],
    "attack_chain_analysis": "How these vulnerabilities could be chained together",
    "executive_summary": "Overall security posture assessment"
}}"""
        
        try:
            response = await self.client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[
                    {
                        "role": "system",
                        "content": "You are an expert penetration tester and security architect. Provide detailed, actionable security analysis with MITRE ATT&CK mappings. Always respond with valid JSON. Be specific about code fixes, not generic advice."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.3,
                max_tokens=4000
            )
            
            import json
            result_text = response.choices[0].message.content
            
            # Parse JSON response
            try:
                result = json.loads(result_text)
            except json.JSONDecodeError:
                if "```json" in result_text:
                    result_text = result_text.split("```json")[1].split("```")[0]
                    result = json.loads(result_text)
                elif "```" in result_text:
                    result_text = result_text.split("```")[1].split("```")[0]
                    result = json.loads(result_text)
                else:
                    raise
            
            logger.info(f"Groq analysis complete for {len(vulnerabilities)} vulnerabilities with MITRE mapping")
            return result
        
        except Exception as e:
            logger.error(f"Groq analysis failed: {e}")
            raise
    
    async def generate_executive_summary(
        self,
        vulnerabilities: List[Dict[str, Any]],
        risk_score: float,
        risk_level: str,
        threat_intel: Optional[Dict[str, Any]] = None
    ) -> str:
        """Generate executive summary using Groq with MITRE ATT&CK context"""
        
        # Prepare top vulnerabilities for context
        top_vulns = self._prepare_vulnerability_summary(vulnerabilities[:5]) if vulnerabilities else "None detected"
        
        # Prepare threat intel summary
        threat_intel_summary = self._prepare_threat_intel_summary(threat_intel) if threat_intel else "No external threat intelligence collected"
        
        # Extract MITRE techniques from vulnerabilities if available
        mitre_techniques = set()
        for v in vulnerabilities:
            if v.get('mitre_techniques'):
                for t in v.get('mitre_techniques', []):
                    if isinstance(t, dict):
                        mitre_techniques.add(f"{t.get('id', '')} ({t.get('name', '')})")
                    elif isinstance(t, str):
                        mitre_techniques.add(t)
        
        mitre_context = f"\nMITRE ATT&CK Techniques Identified: {', '.join(list(mitre_techniques)[:10])}" if mitre_techniques else ""
        
        prompt = f"""Analyze this security scan and generate a technical summary for security professionals.

SCAN METRICS:
- Total Vulnerabilities: {len(vulnerabilities)}
- Risk Score: {risk_score:.1f}/10 ({risk_level})
- Critical: {sum(1 for v in vulnerabilities if v.get('severity') == 'critical')}
- High: {sum(1 for v in vulnerabilities if v.get('severity') == 'high')}
- Medium: {sum(1 for v in vulnerabilities if v.get('severity') == 'medium')}
- Low: {sum(1 for v in vulnerabilities if v.get('severity') == 'low')}{mitre_context}

TOP FINDINGS:
{top_vulns}

EXTERNAL THREAT INTELLIGENCE:
{threat_intel_summary}

GENERATE A TECHNICAL SUMMARY (4 paragraphs, third person):

1. SECURITY POSTURE & ATTACK SURFACE: Assess the target's security state. Reference specific vulnerability types found (e.g., XSS, SQL injection, misconfigurations). Include external reputation data if available. Mention MITRE ATT&CK techniques that map to findings. Be direct about severity.

2. EXTERNAL THREAT LANDSCAPE: Summarize what external intelligence sources reveal about this target. Include VirusTotal results, AbuseIPDB reputation, Shodan exposure (open ports, services), breach history, and Safe Browsing status. If external intel shows concerning indicators, highlight them with specific data points.

3. TECHNICAL RISKS & ATTACK CHAINS: Identify the most critical attack vectors combining scan findings with external intel. Explain how an attacker could chain vulnerabilities together (e.g., "Initial access via T1190 could lead to..."). Reference CVE IDs, CWE categories, MITRE technique IDs, or Shodan-detected services.

4. REMEDIATION PRIORITIES & DEFENSIVE MEASURES: Provide specific, actionable remediation steps ordered by priority. Include:
   - Immediate mitigations (within 24-48 hours)
   - Code-level fixes with specific guidance
   - Infrastructure hardening (WAF rules, network segmentation)
   - Detection recommendations (SIEM rules, log monitoring)

RULES:
- Write in third person ("The target application...", "The scan identified...", "Administrators should...")
- Be technical and specific - this is for security professionals
- Reference MITRE ATT&CK technique IDs where applicable (e.g., T1190, T1059.007)
- Integrate external threat intel findings naturally into the narrative
- Do NOT include any headers like "Executive Summary" or "Security Assessment"
- Do NOT use markdown formatting (no **, ##, or bullet points)
- Keep each paragraph 3-5 sentences
- If no vulnerabilities found but external intel shows concerns, focus on those
- If both vulnerabilities and external concerns are minimal, state the target has a strong security posture"""
        
        try:
            response = await self.client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[
                    {
                        "role": "system",
                        "content": "You are a senior penetration tester and threat intelligence analyst writing technical security reports. Be concise, technical, and actionable. Always reference MITRE ATT&CK techniques when discussing attack patterns. Never use first person. Never include section headers in your output. Integrate threat intelligence findings naturally."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.4,
                max_tokens=1200
            )
            
            return response.choices[0].message.content.strip()
        
        except Exception as e:
            logger.error(f"Executive summary generation failed: {e}")
            raise
    
    def _prepare_threat_intel_summary(self, threat_intel: Dict[str, Any]) -> str:
        """Prepare threat intelligence data for LLM analysis"""
        if not threat_intel:
            return "No external threat intelligence available"
        
        parts = []
        
        # Reputation
        reputation = threat_intel.get("reputation", {})
        if reputation.get("score") is not None:
            parts.append(f"Reputation Score: {reputation.get('score')}/100 ({reputation.get('risk_level', 'Unknown')} risk)")
        
        # VirusTotal
        vt = threat_intel.get("virustotal", {})
        if vt and vt.get("status") != "not_found":
            parts.append(f"VirusTotal: {vt.get('malicious', 0)} malicious, {vt.get('suspicious', 0)} suspicious, {vt.get('harmless', 0)} clean detections")
        
        # Google Safe Browsing
        gsb = threat_intel.get("google_safe_browsing", {})
        if gsb:
            status = "FLAGGED - " + ", ".join(gsb.get("threat_types", [])) if gsb.get("is_flagged") else "Clean"
            parts.append(f"Google Safe Browsing: {status}")
        
        # AbuseIPDB
        abuse = threat_intel.get("abuseipdb", {})
        if abuse and abuse.get("ip_address"):
            parts.append(f"AbuseIPDB: {abuse.get('abuse_confidence_score', 0)}% confidence, {abuse.get('total_reports', 0)} reports, ISP: {abuse.get('isp', 'Unknown')}")
        
        # Shodan
        shodan = threat_intel.get("shodan", {})
        if shodan and shodan.get("ip"):
            parts.append(f"Shodan: {shodan.get('open_ports_count', 0)} open ports, {shodan.get('vuln_count', 0)} known vulnerabilities, Services: {', '.join(shodan.get('services', [])[:5]) or 'None detected'}")
        
        # Breach data
        leak = threat_intel.get("leak_lookup", {})
        if leak:
            if leak.get("has_breaches") or leak.get("breaches_found"):
                parts.append(f"Breach History: {leak.get('breaches_found', 'Multiple')} breaches detected")
            else:
                parts.append("Breach History: No breaches found")
        
        # Risk indicators
        indicators = threat_intel.get("risk_indicators", [])
        if indicators:
            indicator_summary = ", ".join([f"{i.get('type')} ({i.get('severity')})" for i in indicators[:3]])
            parts.append(f"Risk Indicators: {len(indicators)} active - {indicator_summary}")
        
        return "\n".join(parts) if parts else "External intelligence queries returned no significant findings"
    
    def _prepare_vulnerability_summary(self, vulnerabilities: List[Dict]) -> str:
        """Prepare vulnerability data for LLM analysis"""
        summary = ""
        for i, vuln in enumerate(vulnerabilities, 1):
            summary += f"""
{i}. {vuln.get('title', 'Unknown')}
   Severity: {vuln.get('severity', 'Unknown')}
   CVSS: {vuln.get('cvss_score', 'N/A')}
   Location: {vuln.get('location', 'Unknown')}
   Description: {vuln.get('description', 'No description')}
"""
        return summary


class AnthropicProvider(LLMProvider):
    """Anthropic Claude integration"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv('ANTHROPIC_API_KEY')  # Not in settings yet
        if not self.api_key:
            raise ValueError("ANTHROPIC_API_KEY environment variable not set")
        
        try:
            import anthropic
            self.client = anthropic.AsyncAnthropic(api_key=self.api_key)
        except ImportError:
            raise ImportError("anthropic package not installed. Run: pip install anthropic")
    
    async def analyze_vulnerabilities(
        self,
        vulnerabilities: List[Dict[str, Any]],
        target_url: str,
        business_context: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Analyze vulnerabilities using Claude with detailed remediation and MITRE mapping
        """
        if not vulnerabilities:
            return {"recommendations": [], "summary": "No vulnerabilities found"}
        
        vuln_summary = self._prepare_vulnerability_summary(vulnerabilities[:10])
        
        prompt = f"""You are a senior penetration tester and security architect analyzing vulnerability scan results.

Target: {target_url}
{f'Business Context: {business_context}' if business_context else ''}

Found Vulnerabilities:
{vuln_summary}

For EACH vulnerability, provide comprehensive analysis:

1. SEVERITY ASSESSMENT (1-10 scale with justification)
2. MITRE ATT&CK MAPPING:
   - Primary Technique ID and Name (e.g., T1190 - Exploit Public-Facing Application)
   - Associated Tactic (e.g., Initial Access, Execution)
   - Sub-techniques if applicable
3. DETAILED REMEDIATION STEPS:
   - Immediate mitigation (what to do RIGHT NOW)
   - Code-level fix (specific code changes or configurations)
   - Infrastructure hardening (WAF rules, network controls)
   - Long-term prevention (architectural changes)
4. EXPLOITATION SCENARIO: How an attacker would exploit this
5. BUSINESS IMPACT: Data breach risk, compliance violations
6. FIX COMPLEXITY: low/medium/high with time estimate
7. DETECTION METHODS: How to detect exploitation attempts

Format as JSON:
{{
    "vulnerabilities": [
        {{
            "title": "...",
            "severity_score": 1-10,
            "severity_justification": "...",
            "mitre_attack": {{
                "technique_id": "T1XXX",
                "technique_name": "...",
                "tactic": "...",
                "sub_techniques": ["T1XXX.XXX"]
            }},
            "remediation": {{
                "immediate": ["step1", "step2"],
                "code_fix": ["specific code/config changes"],
                "infrastructure": ["WAF rules, network controls"],
                "long_term": ["architectural improvements"]
            }},
            "exploitation_scenario": "...",
            "business_impact": "...",
            "fix_complexity": "low|medium|high",
            "estimated_fix_time": "X hours/days",
            "detection_methods": ["log patterns", "alerts"]
        }}
    ],
    "attack_chain_analysis": "How vulnerabilities could be chained",
    "executive_summary": "Overall security posture"
}}"""
        
        try:
            response = await self.client.messages.create(
                model="claude-3-5-sonnet-20241022",
                max_tokens=4000,
                system="You are an expert penetration tester and security architect. Provide detailed, actionable security analysis with MITRE ATT&CK mappings. Always respond with valid JSON. Be specific about code fixes.",
                messages=[
                    {
                        "role": "user",
                        "content": prompt
                    }
                ]
            )
            
            import json
            result_text = response.content[0].text
            
            # Parse JSON
            try:
                result = json.loads(result_text)
            except json.JSONDecodeError:
                if "```json" in result_text:
                    result_text = result_text.split("```json")[1].split("```")[0]
                    result = json.loads(result_text)
                elif "```" in result_text:
                    result_text = result_text.split("```")[1].split("```")[0]
                    result = json.loads(result_text)
                else:
                    raise
            
            logger.info(f"Claude analysis complete for {len(vulnerabilities)} vulnerabilities with MITRE mapping")
            return result
        
        except Exception as e:
            logger.error(f"Claude analysis failed: {e}")
            raise
    
    async def generate_executive_summary(
        self,
        vulnerabilities: List[Dict[str, Any]],
        risk_score: float,
        risk_level: str,
        threat_intel: Optional[Dict[str, Any]] = None
    ) -> str:
        """Generate executive summary using Claude with MITRE ATT&CK context"""
        
        # Prepare top vulnerabilities for context
        top_vulns = self._prepare_vulnerability_summary(vulnerabilities[:5]) if vulnerabilities else "None detected"
        
        # Prepare threat intel summary
        threat_intel_summary = self._prepare_threat_intel_summary(threat_intel) if threat_intel else "No external threat intelligence collected"
        
        # Extract MITRE techniques from vulnerabilities if available
        mitre_techniques = set()
        for v in vulnerabilities:
            if v.get('mitre_techniques'):
                for t in v.get('mitre_techniques', []):
                    if isinstance(t, dict):
                        mitre_techniques.add(f"{t.get('id', '')} ({t.get('name', '')})")
                    elif isinstance(t, str):
                        mitre_techniques.add(t)
        
        mitre_context = f"\nMITRE ATT&CK Techniques Identified: {', '.join(list(mitre_techniques)[:10])}" if mitre_techniques else ""
        
        prompt = f"""Analyze this security scan and generate a technical summary for security professionals.

SCAN METRICS:
- Total Vulnerabilities: {len(vulnerabilities)}
- Risk Score: {risk_score:.1f}/10 ({risk_level})
- Critical: {sum(1 for v in vulnerabilities if v.get('severity') == 'critical')}
- High: {sum(1 for v in vulnerabilities if v.get('severity') == 'high')}
- Medium: {sum(1 for v in vulnerabilities if v.get('severity') == 'medium')}
- Low: {sum(1 for v in vulnerabilities if v.get('severity') == 'low')}{mitre_context}

TOP FINDINGS:
{top_vulns}

EXTERNAL THREAT INTELLIGENCE:
{threat_intel_summary}

GENERATE A TECHNICAL SUMMARY (4 paragraphs, third person):

1. SECURITY POSTURE & ATTACK SURFACE: Assess the target's security state. Reference specific vulnerability types found. Include MITRE ATT&CK techniques. Be direct about severity.

2. EXTERNAL THREAT LANDSCAPE: Summarize what external intelligence sources reveal. Include VirusTotal, AbuseIPDB, Shodan, breach history.

3. TECHNICAL RISKS & ATTACK CHAINS: Identify attack vectors. Explain how vulnerabilities could be chained. Reference MITRE technique IDs.

4. REMEDIATION PRIORITIES & DEFENSIVE MEASURES: Specific, actionable remediation steps. Include immediate mitigations, code fixes, infrastructure hardening, detection recommendations.

RULES:
- Write in third person
- Be technical and specific
- Reference MITRE ATT&CK technique IDs where applicable
- Integrate threat intel findings naturally
- Do NOT include headers or markdown formatting
- Keep paragraphs 3-5 sentences"""
        
        try:
            response = await self.client.messages.create(
                model="claude-3-5-sonnet-20241022",
                max_tokens=1200,
                system="You are a senior penetration tester and threat intelligence analyst writing technical security reports. Be concise, technical, and actionable. Always reference MITRE ATT&CK techniques when discussing attack patterns. Never use first person. Never include section headers in your output.",
                messages=[
                    {
                        "role": "user",
                        "content": prompt
                    }
                ]
            )
            
            return response.content[0].text.strip()
        
        except Exception as e:
            logger.error(f"Executive summary generation failed: {e}")
            raise
    
    def _prepare_threat_intel_summary(self, threat_intel: Dict[str, Any]) -> str:
        """Prepare threat intelligence data for LLM analysis"""
        if not threat_intel:
            return "No external threat intelligence available"
        
        parts = []
        
        reputation = threat_intel.get("reputation", {})
        if reputation.get("score") is not None:
            parts.append(f"Reputation Score: {reputation.get('score')}/100 ({reputation.get('risk_level', 'Unknown')} risk)")
        
        vt = threat_intel.get("virustotal", {})
        if vt and vt.get("status") != "not_found":
            parts.append(f"VirusTotal: {vt.get('malicious', 0)} malicious, {vt.get('suspicious', 0)} suspicious, {vt.get('harmless', 0)} clean detections")
        
        gsb = threat_intel.get("google_safe_browsing", {})
        if gsb:
            status = "FLAGGED - " + ", ".join(gsb.get("threat_types", [])) if gsb.get("is_flagged") else "Clean"
            parts.append(f"Google Safe Browsing: {status}")
        
        abuse = threat_intel.get("abuseipdb", {})
        if abuse and abuse.get("ip_address"):
            parts.append(f"AbuseIPDB: {abuse.get('abuse_confidence_score', 0)}% confidence, {abuse.get('total_reports', 0)} reports")
        
        shodan = threat_intel.get("shodan", {})
        if shodan and shodan.get("ip"):
            parts.append(f"Shodan: {shodan.get('open_ports_count', 0)} open ports, {shodan.get('vuln_count', 0)} known vulnerabilities")
        
        leak = threat_intel.get("leak_lookup", {})
        if leak:
            if leak.get("has_breaches") or leak.get("breaches_found"):
                parts.append(f"Breach History: {leak.get('breaches_found', 'Multiple')} breaches detected")
            else:
                parts.append("Breach History: No breaches found")
        
        indicators = threat_intel.get("risk_indicators", [])
        if indicators:
            parts.append(f"Risk Indicators: {len(indicators)} active")
        
        return "\n".join(parts) if parts else "External intelligence queries returned no significant findings"
    
    def _prepare_vulnerability_summary(self, vulnerabilities: List[Dict]) -> str:
        """Prepare vulnerability data for LLM analysis"""
        summary = ""
        for i, vuln in enumerate(vulnerabilities, 1):
            summary += f"""
{i}. {vuln.get('title', 'Unknown')}
   Severity: {vuln.get('severity', 'Unknown')}
   CVSS: {vuln.get('cvss_score', 'N/A')}
   Location: {vuln.get('location', 'Unknown')}
   Description: {vuln.get('description', 'No description')}
"""
        return summary


class FallbackProvider(LLMProvider):
    """Fallback provider when no LLM is configured"""
    
    async def analyze_vulnerabilities(
        self,
        vulnerabilities: List[Dict[str, Any]],
        target_url: str,
        business_context: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Provide basic analysis without calling external LLM
        """
        logger.warning("Using fallback analysis (no LLM configured)")
        
        # Filter out None entries from vulnerabilities
        vulnerabilities = [v for v in vulnerabilities if v is not None]
        
        recommendations = []
        for vuln in vulnerabilities[:10]:
            recommendations.append({
                "title": vuln.get("title", "Unknown"),
                "remediation": [
                    f"Review {vuln.get('title', 'this vulnerability')} in detail",
                    "Apply security patches if available",
                    "Test changes in staging environment"
                ],
                "business_impact": f"High risk for {target_url}",
                "fix_complexity": "medium",
                "priority": min(10, max(1, int(vuln.get('cvss_score', 5))))
            })
        
        return {
            "vulnerabilities": recommendations,
            "executive_summary": f"Scan of {target_url} found {len(vulnerabilities)} vulnerabilities. "
                               f"Please configure LLM integration for detailed analysis."
        }
    
    async def generate_executive_summary(
        self,
        vulnerabilities: List[Dict[str, Any]],
        risk_score: float,
        risk_level: str,
        threat_intel: Optional[Dict[str, Any]] = None
    ) -> str:
        """Generate basic summary when no LLM is configured"""
        
        # Filter out None entries from vulnerabilities
        vulnerabilities = [v for v in vulnerabilities if v is not None]
        
        critical = sum(1 for v in vulnerabilities if v.get('severity') == 'critical')
        high = sum(1 for v in vulnerabilities if v.get('severity') == 'high')
        medium = sum(1 for v in vulnerabilities if v.get('severity') == 'medium')
        low = sum(1 for v in vulnerabilities if v.get('severity') == 'low')
        
        # Build threat intel summary
        intel_summary = ""
        if threat_intel:
            reputation = threat_intel.get("reputation", {})
            vt = threat_intel.get("virustotal", {})
            gsb = threat_intel.get("google_safe_browsing", {})
            shodan = threat_intel.get("shodan", {})
            
            intel_parts = []
            if reputation.get("score") is not None:
                intel_parts.append(f"reputation score of {reputation.get('score')}/100")
            if vt.get("malicious", 0) > 0:
                intel_parts.append(f"{vt.get('malicious')} VirusTotal detections")
            if gsb.get("is_flagged"):
                intel_parts.append("flagged by Google Safe Browsing")
            if shodan.get("vuln_count", 0) > 0:
                intel_parts.append(f"{shodan.get('vuln_count')} Shodan-identified vulnerabilities")
            
            if intel_parts:
                intel_summary = f" External intelligence reveals {', '.join(intel_parts)}."
        
        if not vulnerabilities:
            base_msg = ("The target application demonstrates a strong security posture with no vulnerabilities detected during this scan. "
                       "However, security is an ongoing process and administrators should implement continuous monitoring, "
                       "regular dependency updates, and periodic penetration testing to maintain this secure state.")
            if intel_summary:
                base_msg += intel_summary
            return base_msg
        
        # Build severity description
        severity_parts = []
        if critical > 0:
            severity_parts.append(f"{critical} critical")
        if high > 0:
            severity_parts.append(f"{high} high")
        if medium > 0:
            severity_parts.append(f"{medium} medium")
        if low > 0:
            severity_parts.append(f"{low} low")
        severity_desc = ", ".join(severity_parts) if severity_parts else "various"
        
        # Get top vulnerability types
        vuln_types = set()
        for v in vulnerabilities[:10]:
            title = v.get('title', '').lower()
            if 'xss' in title or 'cross-site' in title:
                vuln_types.add('Cross-Site Scripting (XSS)')
            elif 'sql' in title or 'injection' in title:
                vuln_types.add('SQL Injection')
            elif 'csrf' in title:
                vuln_types.add('CSRF')
            elif 'header' in title or 'csp' in title or 'hsts' in title:
                vuln_types.add('missing security headers')
            elif 'ssl' in title or 'tls' in title or 'certificate' in title:
                vuln_types.add('TLS/SSL issues')
            elif 'auth' in title or 'session' in title:
                vuln_types.add('authentication weaknesses')
        
        types_desc = ", ".join(list(vuln_types)[:3]) if vuln_types else "security misconfigurations"
        
        paragraph1 = (f"The scan identified {len(vulnerabilities)} vulnerabilities across the target application "
                      f"with a risk score of {risk_score:.1f}/10 ({risk_level}). "
                      f"The severity breakdown includes {severity_desc} severity findings, "
                      f"with notable issues including {types_desc}.")
        
        paragraph2 = ("These findings indicate potential attack vectors that could be exploited by malicious actors. "
                      "Critical and high severity issues should be treated as immediate priorities as they may allow "
                      "unauthorized access, data exfiltration, or service disruption.")
        
        paragraph3 = ("Administrators should prioritize patching critical vulnerabilities first, implement proper input validation, "
                      "configure security headers (CSP, HSTS, X-Frame-Options), and ensure all dependencies are updated. "
                      "Configure an LLM provider (Groq/OpenAI/Anthropic) for detailed AI-powered remediation guidance.")
        
        return f"{paragraph1}\n\n{paragraph2}\n\n{paragraph3}"


class LLMService:
    """Main LLM service - handles provider selection and fallback"""
    
    _instance = None
    _provider = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialize_provider()
        return cls._instance
    
    def _initialize_provider(self):
        """Initialize the appropriate LLM provider with fallback support"""
        # Priority: Groq (free, fast, llama-3.3-70b) > OpenAI (gpt-4o-mini) > Anthropic (claude-3.5-sonnet) > Fallback
        
        if settings.GROQ_API_KEY:
            try:
                self._provider = GroqProvider()
                logger.info("✓ LLM Service initialized with Groq (Llama 3.3-70b-versatile) - Primary provider")
            except Exception as e:
                logger.warning(f"Groq initialization failed: {e}")
                self._try_alternative_providers()
        
        elif settings.OPENAI_API_KEY:
            try:
                self._provider = OpenAIProvider()
                logger.info("✓ LLM Service initialized with OpenAI (GPT-4o-mini)")
            except Exception as e:
                logger.warning(f"OpenAI initialization failed: {e}, trying Anthropic")
                if os.getenv('ANTHROPIC_API_KEY'):
                    try:
                        self._provider = AnthropicProvider()
                        logger.info("✓ LLM Service initialized with Anthropic (Claude 3.5 Sonnet)")
                    except Exception as e2:
                        logger.warning(f"Anthropic initialization failed: {e2}, using fallback")
                        self._provider = FallbackProvider()
                else:
                    self._provider = FallbackProvider()
        
        elif os.getenv('ANTHROPIC_API_KEY'):
            try:
                self._provider = AnthropicProvider()
                logger.info("LLM Service: Using Anthropic Claude")
            except Exception as e:
                logger.warning(f"Anthropic initialization failed: {e}, using fallback")
                self._provider = FallbackProvider()
        
        else:
            logger.warning("No LLM API keys configured, using fallback provider")
            self._provider = FallbackProvider()
    
    def _try_alternative_providers(self):
        """Try alternative providers if primary fails"""
        if settings.OPENAI_API_KEY:
            try:
                self._provider = OpenAIProvider()
                logger.info("LLM Service: Fallback to OpenAI GPT-3.5")
                return
            except Exception:
                pass
        
        if os.getenv('ANTHROPIC_API_KEY'):
            try:
                self._provider = AnthropicProvider()
                logger.info("LLM Service: Fallback to Anthropic Claude")
                return
            except Exception:
                pass
        
        logger.warning("All LLM providers failed, using fallback")
        self._provider = FallbackProvider()
    
    async def analyze_vulnerabilities(
        self,
        vulnerabilities: List[Dict[str, Any]],
        target_url: str,
        business_context: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Analyze vulnerabilities using configured LLM
        
        Args:
            vulnerabilities: List of vulnerability findings
            target_url: URL being scanned
            business_context: Optional business context
        
        Returns:
            Dict with AI analysis and recommendations
        """
        try:
            result = await self._provider.analyze_vulnerabilities(
                vulnerabilities,
                target_url,
                business_context
            )
            return result
        except Exception as e:
            logger.error(f"LLM analysis failed: {e}")
            # Return fallback
            return await FallbackProvider().analyze_vulnerabilities(
                vulnerabilities,
                target_url,
                business_context
            )
    
    async def generate_executive_summary(
        self,
        vulnerabilities: List[Dict[str, Any]],
        risk_score: float,
        risk_level: str,
        threat_intel: Optional[Dict[str, Any]] = None
    ) -> str:
        """Generate executive summary"""
        try:
            return await self._provider.generate_executive_summary(
                vulnerabilities,
                risk_score,
                risk_level,
                threat_intel
            )
        except Exception as e:
            logger.error(f"Executive summary generation failed: {e}")
            return await FallbackProvider().generate_executive_summary(
                vulnerabilities,
                risk_score,
                risk_level,
                threat_intel
            )


# Singleton instance
llm_service = LLMService()
