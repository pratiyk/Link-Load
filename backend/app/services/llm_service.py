"""
LLM Integration Service for AI-powered security analysis.

Supports:
- OpenAI GPT-4
- Anthropic Claude
- Fallback mechanism

Run: Configure OPENAI_API_KEY or ANTHROPIC_API_KEY in .env
"""

import os
import asyncio
from typing import Optional, List, Dict, Any
from abc import ABC, abstractmethod
import logging

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
        risk_level: str
    ) -> str:
        """Generate executive summary of scan results"""
        pass


class OpenAIProvider(LLMProvider):
    """OpenAI GPT-4 integration"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv('OPENAI_API_KEY')
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
        Analyze vulnerabilities using GPT-4
        
        Args:
            vulnerabilities: List of vulnerability objects
            target_url: Target URL being scanned
            business_context: Optional business context for analysis
        
        Returns:
            Dict with recommendations and analysis
        """
        if not vulnerabilities:
            return {"recommendations": [], "summary": "No vulnerabilities found"}
        
        # Prepare vulnerability summary for LLM
        vuln_summary = self._prepare_vulnerability_summary(vulnerabilities[:10])  # Top 10
        
        prompt = f"""
        You are a senior security researcher analyzing vulnerability scan results.
        
        Target: {target_url}
        {f'Business Context: {business_context}' if business_context else ''}
        
        Found Vulnerabilities:
        {vuln_summary}
        
        For each vulnerability, provide:
        1. Severity assessment (1-10 scale)
        2. Specific remediation steps (2-3 actionable items)
        3. Business impact if exploited
        4. Estimated fix complexity (low/medium/high)
        
        Format as JSON with structure:
        {{
            "vulnerabilities": [
                {{
                    "title": "...",
                    "remediation": ["step1", "step2", ...],
                    "business_impact": "...",
                    "fix_complexity": "...",
                    "priority": 1-10
                }},
                ...
            ],
            "executive_summary": "..."
        }}
        """
        
        try:
            response = await self.client.chat.completions.create(
                model="gpt-3.5-turbo",  # Using GPT-3.5-turbo for better compatibility
                messages=[
                    {
                        "role": "system",
                        "content": "You are a cybersecurity expert. Always respond with valid JSON."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.7,
                max_tokens=2000,
                timeout=30
            )
            
            import json
            result_text = response.choices[0].message.content
            
            # Parse JSON response
            try:
                result = json.loads(result_text)
            except json.JSONDecodeError:
                # Extract JSON if wrapped in markdown
                if "```json" in result_text:
                    result_text = result_text.split("```json")[1].split("```")[0]
                    result = json.loads(result_text)
                else:
                    raise
            
            logger.info(f"GPT-4 analysis complete for {len(vulnerabilities)} vulnerabilities")
            return result
        
        except Exception as e:
            logger.error(f"OpenAI analysis failed: {e}")
            raise
    
    async def generate_executive_summary(
        self,
        vulnerabilities: List[Dict[str, Any]],
        risk_score: float,
        risk_level: str
    ) -> str:
        """Generate executive summary using GPT-4"""
        
        prompt = f"""
        Generate a concise executive summary (2-3 paragraphs) of security scan results.
        
        Total Vulnerabilities: {len(vulnerabilities)}
        Risk Score: {risk_score}/10
        Risk Level: {risk_level}
        
        Severity Breakdown:
        - Critical: {sum(1 for v in vulnerabilities if v.get('severity') == 'critical')}
        - High: {sum(1 for v in vulnerabilities if v.get('severity') == 'high')}
        - Medium: {sum(1 for v in vulnerabilities if v.get('severity') == 'medium')}
        - Low: {sum(1 for v in vulnerabilities if v.get('severity') == 'low')}
        
        Format:
        1. Current state assessment
        2. Key risks
        3. Recommended actions
        """
        
        try:
            response = await self.client.chat.completions.create(
                model="gpt-3.5-turbo",  # Using GPT-3.5-turbo for better compatibility
                messages=[
                    {
                        "role": "system",
                        "content": "You are a cybersecurity executive summarizing scan results."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.7,
                max_tokens=500,
                timeout=15
            )
            
            return response.choices[0].message.content
        
        except Exception as e:
            logger.error(f"Executive summary generation failed: {e}")
            raise
    
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
        self.api_key = api_key or os.getenv('GROQ_API_KEY')
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
        Analyze vulnerabilities using Groq (Mixtral or Llama)
        """
        if not vulnerabilities:
            return {"recommendations": [], "summary": "No vulnerabilities found"}
        
        vuln_summary = self._prepare_vulnerability_summary(vulnerabilities[:10])
        
        prompt = f"""
        You are a senior security researcher analyzing vulnerability scan results.
        
        Target: {target_url}
        {f'Business Context: {business_context}' if business_context else ''}
        
        Found Vulnerabilities:
        {vuln_summary}
        
        For each vulnerability, provide:
        1. Severity assessment (1-10 scale)
        2. Specific remediation steps (2-3 actionable items)
        3. Business impact if exploited
        4. Estimated fix complexity (low/medium/high)
        
        Format as JSON with structure:
        {{
            "vulnerabilities": [
                {{
                    "title": "...",
                    "remediation": ["step1", "step2", ...],
                    "business_impact": "...",
                    "fix_complexity": "...",
                    "priority": 1-10
                }},
                ...
            ],
            "executive_summary": "..."
        }}
        """
        
        try:
            response = await self.client.chat.completions.create(
                model="llama-3.3-70b-versatile",  # Fast, capable, and free model
                messages=[
                    {
                        "role": "system",
                        "content": "You are a cybersecurity expert. Always respond with valid JSON."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.7,
                max_tokens=2000
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
                else:
                    raise
            
            logger.info(f"Groq analysis complete for {len(vulnerabilities)} vulnerabilities")
            return result
        
        except Exception as e:
            logger.error(f"Groq analysis failed: {e}")
            raise
    
    async def generate_executive_summary(
        self,
        vulnerabilities: List[Dict[str, Any]],
        risk_score: float,
        risk_level: str
    ) -> str:
        """Generate executive summary using Groq"""
        
        prompt = f"""
        Generate a concise executive summary (2-3 paragraphs) of security scan results.
        
        Total Vulnerabilities: {len(vulnerabilities)}
        Risk Score: {risk_score}/10
        Risk Level: {risk_level}
        
        Severity Breakdown:
        - Critical: {sum(1 for v in vulnerabilities if v.get('severity') == 'critical')}
        - High: {sum(1 for v in vulnerabilities if v.get('severity') == 'high')}
        - Medium: {sum(1 for v in vulnerabilities if v.get('severity') == 'medium')}
        - Low: {sum(1 for v in vulnerabilities if v.get('severity') == 'low')}
        """
        
        try:
            response = await self.client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[
                    {
                        "role": "system",
                        "content": "You are a cybersecurity executive summarizing scan results."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.7,
                max_tokens=500
            )
            
            return response.choices[0].message.content
        
        except Exception as e:
            logger.error(f"Executive summary generation failed: {e}")
            raise
    
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
        self.api_key = api_key or os.getenv('ANTHROPIC_API_KEY')
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
        Analyze vulnerabilities using Claude
        
        Similar to OpenAI but uses Claude API
        """
        if not vulnerabilities:
            return {"recommendations": [], "summary": "No vulnerabilities found"}
        
        vuln_summary = self._prepare_vulnerability_summary(vulnerabilities[:10])
        
        prompt = f"""
        You are a senior security researcher analyzing vulnerability scan results.
        
        Target: {target_url}
        {f'Business Context: {business_context}' if business_context else ''}
        
        Found Vulnerabilities:
        {vuln_summary}
        
        For each vulnerability, provide:
        1. Severity assessment (1-10 scale)
        2. Specific remediation steps (2-3 actionable items)
        3. Business impact if exploited
        4. Estimated fix complexity (low/medium/high)
        
        Format as JSON:
        {{
            "vulnerabilities": [
                {{
                    "title": "...",
                    "remediation": ["step1", "step2", ...],
                    "business_impact": "...",
                    "fix_complexity": "...",
                    "priority": 1-10
                }},
                ...
            ],
            "executive_summary": "..."
        }}
        """
        
        try:
            response = await self.client.messages.create(
                model="claude-3-sonnet-20240229",
                max_tokens=2000,
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
                else:
                    raise
            
            logger.info(f"Claude analysis complete for {len(vulnerabilities)} vulnerabilities")
            return result
        
        except Exception as e:
            logger.error(f"Claude analysis failed: {e}")
            raise
    
    async def generate_executive_summary(
        self,
        vulnerabilities: List[Dict[str, Any]],
        risk_score: float,
        risk_level: str
    ) -> str:
        """Generate executive summary using Claude"""
        
        prompt = f"""
        Generate a concise executive summary (2-3 paragraphs) of security scan results.
        
        Total Vulnerabilities: {len(vulnerabilities)}
        Risk Score: {risk_score}/10
        Risk Level: {risk_level}
        
        Severity Breakdown:
        - Critical: {sum(1 for v in vulnerabilities if v.get('severity') == 'critical')}
        - High: {sum(1 for v in vulnerabilities if v.get('severity') == 'high')}
        - Medium: {sum(1 for v in vulnerabilities if v.get('severity') == 'medium')}
        - Low: {sum(1 for v in vulnerabilities if v.get('severity') == 'low')}
        """
        
        try:
            response = await self.client.messages.create(
                model="claude-3-sonnet-20240229",
                max_tokens=500,
                messages=[
                    {
                        "role": "user",
                        "content": prompt
                    }
                ]
            )
            
            return response.content[0].text
        
        except Exception as e:
            logger.error(f"Executive summary generation failed: {e}")
            raise
    
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
        risk_level: str
    ) -> str:
        """Generate basic summary"""
        return f"""
Security Scan Summary:
- Total Issues Found: {len(vulnerabilities)}
- Risk Level: {risk_level}
- Risk Score: {risk_score}/10

This is a basic summary. Configure LLM integration (OpenAI/Claude) 
in environment variables for detailed analysis and recommendations.
"""


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
        """Initialize the appropriate LLM provider"""
        # Priority: Groq (free, fast) > OpenAI > Anthropic > Fallback
        if os.getenv('GROQ_API_KEY'):
            try:
                self._provider = GroqProvider()
                logger.info("LLM Service: Using Groq (Mixtral)")
            except Exception as e:
                logger.warning(f"Groq initialization failed: {e}, trying alternatives")
                self._try_alternative_providers()
        
        elif os.getenv('OPENAI_API_KEY'):
            try:
                self._provider = OpenAIProvider()
                logger.info("LLM Service: Using OpenAI GPT-3.5")
            except Exception as e:
                logger.warning(f"OpenAI initialization failed: {e}, using fallback")
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
        if os.getenv('OPENAI_API_KEY'):
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
        risk_level: str
    ) -> str:
        """Generate executive summary"""
        try:
            return await self._provider.generate_executive_summary(
                vulnerabilities,
                risk_score,
                risk_level
            )
        except Exception as e:
            logger.error(f"Executive summary generation failed: {e}")
            return await FallbackProvider().generate_executive_summary(
                vulnerabilities,
                risk_score,
                risk_level
            )


# Singleton instance
llm_service = LLMService()
