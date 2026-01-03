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
import json
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
            if result_text is None:
                raise ValueError("OpenAI response content is None")
            try:
                result = json.loads(result_text)
            except json.JSONDecodeError:
                if isinstance(result_text, str) and "```json" in result_text:
                    result_text = result_text.split("```json")[1].split("````")[0]
                    result = json.loads(result_text)
                elif isinstance(result_text, str) and "```" in result_text:
                    result_text = result_text.split("```")[1].split("````")[0]
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
            
            content = response.choices[0].message.content
            if content is None:
                return ""
            return content.strip()
        
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

    async def _complete_chat(
        self,
        messages: List[Dict[str, Any]],
        *,
        temperature: float,
        max_tokens: int
    ) -> str:
        """Call Groq chat completion with retries and normalized output."""
        last_error: Optional[Exception] = None
        for attempt in range(2):
            try:
                response = await self.client.chat.completions.create(
                    model="llama-3.3-70b-versatile",
                    messages=messages,
                    temperature=temperature,
                    max_tokens=max_tokens
                )
                content = self._extract_message_content(response)
                if content:
                    return content.strip()
                raise ValueError("Groq response missing content/choices")
            except Exception as exc:  # noqa: PERF203 - explicit retries
                last_error = exc
                logger.warning(
                    "Groq chat completion attempt %s failed: %s",
                    attempt + 1,
                    exc
                )
        raise last_error or ValueError("Groq response missing content after retries")

    def _extract_message_content(self, response: Any) -> Optional[str]:
        """Normalize Groq response payloads to a raw text string."""
        if response is None:
            return None

        choices = getattr(response, "choices", None)
        if choices is None and isinstance(response, dict):
            choices = response.get("choices")

        if choices:
            first_choice = choices[0]
            message = getattr(first_choice, "message", None)
            if message is None and isinstance(first_choice, dict):
                message = first_choice.get("message")

            if message is not None:
                content = getattr(message, "content", None)
                if content is None and isinstance(message, dict):
                    content = message.get("content")
                if isinstance(content, list):
                    content = " ".join(
                        [
                            segment.get("text", "") if isinstance(segment, dict) else str(segment)
                            for segment in content
                        ]
                    )
                if content:
                    return str(content)

            text_attr = getattr(first_choice, "text", None)
            if text_attr:
                return str(text_attr)
            if isinstance(first_choice, dict):
                text_value = first_choice.get("text") or first_choice.get("content")
                if text_value:
                    return str(text_value)

        # Some Groq clients return aggregated text helpers
        if hasattr(response, "output_text"):
            output_text = getattr(response, "output_text")
            if output_text:
                return str(output_text)
        if isinstance(response, dict):
            return response.get("output_text") or response.get("content")
        return None

    def _clean_json_payload(self, raw_text: str) -> str:
        """Strip code fences and extraneous characters before JSON parsing."""
        if not raw_text:
            return ""

        cleaned = raw_text.strip()
        for fence in ("```json", "```JSON", "```"):
            if fence in cleaned:
                parts = cleaned.split(fence, 1)
                if len(parts) > 1:
                    cleaned = parts[1]
                if "```" in cleaned:
                    cleaned = cleaned.split("```", 1)[0]
                break

        cleaned = cleaned.strip("`\n\r \t")
        start = cleaned.find("{")
        end = cleaned.rfind("}")
        if start != -1 and end != -1 and end > start:
            cleaned = cleaned[start:end + 1]
        return cleaned

    def _parse_json_response(self, raw_text: str) -> Optional[Dict[str, Any]]:
        """Parse Groq JSON payload safely, returning None on failure."""
        if not raw_text:
            return None

        cleaned = self._clean_json_payload(raw_text)
        if not cleaned:
            return None

        try:
            return json.loads(cleaned)
        except json.JSONDecodeError as err:
            logger.warning("Groq JSON parsing failed: %s", err)
            return None

    def _empty_analysis_result(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Provide structured fallback when Groq output cannot be parsed."""
        severity_map = {
            "critical": 9,
            "high": 8,
            "medium": 6,
            "low": 4,
            "info": 2
        }

        fallback_entries: List[Dict[str, Any]] = []
        for vuln in vulnerabilities:
            severity_key = str(vuln.get("severity", "medium")).lower()
            fallback_entries.append({
                "title": vuln.get("title", "Unknown"),
                "severity_score": severity_map.get(severity_key, 5),
                "severity_justification": "LLM analysis unavailable; derived from scanner severity.",
                "mitre_attack": {
                    "technique_id": "",
                    "technique_name": "",
                    "tactic": "",
                    "sub_techniques": []
                },
                "remediation": {
                    "immediate": [],
                    "code_fix": [],
                    "infrastructure": [],
                    "long_term": []
                },
                "exploitation_scenario": "LLM analysis unavailable.",
                "business_impact": "LLM analysis unavailable.",
                "fix_complexity": "unknown",
                "estimated_fix_time": "unknown",
                "detection_methods": []
            })

        return {
            "vulnerabilities": fallback_entries,
            "attack_chain_analysis": "LLM analysis unavailable; unable to compute attack chains.",
            "executive_summary": "LLM analysis unavailable; review scanner findings manually."
        }
    
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
            result_text = await self._complete_chat(
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

            result = self._parse_json_response(result_text)
            if result is None:
                raise ValueError("Groq analysis returned an empty or invalid JSON payload")

            logger.info(
                "Groq analysis complete for %s vulnerabilities with MITRE mapping",
                len(vulnerabilities)
            )
            return result

        except Exception as e:
            logger.error("Groq analysis failed, returning fallback payload: %s", e)
            return self._empty_analysis_result(vulnerabilities)
    
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
            content = await self._complete_chat(
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

            return content.strip()

        except Exception as e:
            logger.error(
                "Executive summary generation failed, using fallback summary: %s",
                e
            )
            fallback = FallbackProvider()
            return await fallback.generate_executive_summary(
                vulnerabilities,
                risk_score,
                risk_level,
                threat_intel
            )
    
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
            import importlib
            anthropic = importlib.import_module("anthropic")
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
            result_text = response.content[0].text if response.content and response.content[0].text is not None else None
            if result_text is None:
                raise ValueError("Anthropic response content is None")
            try:
                result = json.loads(result_text)
            except json.JSONDecodeError:
                if isinstance(result_text, str) and "```json" in result_text:
                    result_text = result_text.split("```json")[1].split("````")[0]
                    result = json.loads(result_text)
                elif isinstance(result_text, str) and "```" in result_text:
                    result_text = result_text.split("```")[1].split("````")[0]
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
            
            content = response.content[0].text if response.content and response.content[0].text is not None else None
            if content is None:
                return ""
            return content.strip()
        
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
            if self._provider is None:
                raise ValueError("No LLM provider initialized")
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
            if self._provider is None:
                raise ValueError("No LLM provider initialized")
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
