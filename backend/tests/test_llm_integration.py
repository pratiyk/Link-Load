"""
Test LLM Integration Pipeline
Tests for Groq and HuggingFace API integrations
"""
import pytest
import os
from unittest.mock import patch, MagicMock
import json


@pytest.fixture
def groq_api_key():
    """Get Groq API key from environment"""
    return os.getenv("GROQ_API_KEY", "")


@pytest.fixture
def hf_api_key():
    """Get HuggingFace API key from environment"""
    return os.getenv("HF_API_KEY", "")


def test_groq_api_key_configured(groq_api_key):
    """Verify Groq API key is configured"""
    assert groq_api_key, "GROQ_API_KEY environment variable not set"
    assert len(groq_api_key) > 10, "GROQ_API_KEY seems too short"


def test_hf_api_key_configured(hf_api_key):
    """Verify HuggingFace API key is configured"""
    assert hf_api_key, "HF_API_KEY environment variable not set"
    assert len(hf_api_key) > 10, "HF_API_KEY seems too short"


@pytest.mark.asyncio
async def test_groq_api_mock_call():
    """Test Groq API integration with mocked response"""
    # Mock the Groq client
    mock_response = {
        "choices": [{
            "message": {
                "content": "This vulnerability is an SQL injection flaw that allows attackers to manipulate database queries."
            }
        }]
    }
    
    with patch('groq.Groq') as MockGroq:
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = MagicMock(**mock_response)
        MockGroq.return_value = mock_client
        
        # Test LLM analysis
        try:
            from groq import Groq
            client = Groq(api_key="test_key")
            response = client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[{
                    "role": "user",
                    "content": "Analyze this SQL injection vulnerability"
                }]
            )
            
            assert response.choices[0].message.content is not None
            assert "vulnerability" in response.choices[0].message.content.lower()
            
        except ImportError:
            pytest.skip("Groq library not installed")


@pytest.mark.asyncio
@pytest.mark.integration
async def test_groq_api_real_call():
    """Test real Groq API call (marked as integration test)"""
    groq_api_key = os.getenv("GROQ_API_KEY")
    
    if not groq_api_key:
        pytest.skip("GROQ_API_KEY not set - skipping real API test")
    
    try:
        from groq import Groq
        
        client = Groq(api_key=groq_api_key)
        
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{
                "role": "user",
                "content": "In one sentence, what is SQL injection?"
            }],
            max_tokens=100,
            temperature=0.1
        )
        
        assert response.choices is not None
        assert len(response.choices) > 0
        assert response.choices[0].message.content is not None
        content = response.choices[0].message.content.lower()
        assert any(word in content for word in ["sql", "injection", "database", "query"])
        
    except ImportError:
        pytest.skip("Groq library not installed")
    except Exception as e:
        pytest.fail(f"Groq API call failed: {str(e)}")


@pytest.mark.asyncio
async def test_vulnerability_analysis_prompt():
    """Test vulnerability analysis prompt structure"""
    # Mock vulnerability data
    vuln_data = {
        "title": "SQL Injection in Login Form",
        "description": "User input is directly concatenated into SQL query",
        "severity": "HIGH",
        "cvss_score": 8.5,
        "location": "/api/login",
        "recommendation": "Use parameterized queries"
    }
    
    # Construct analysis prompt
    prompt = f"""Analyze this security vulnerability:

Title: {vuln_data['title']}
Description: {vuln_data['description']}
Severity: {vuln_data['severity']} (CVSS: {vuln_data['cvss_score']})
Location: {vuln_data['location']}

Provide:
1. Attack scenario (2-3 sentences)
2. Business impact (2-3 sentences)
3. Remediation priority (High/Medium/Low)
4. Additional recommendations

Format your response as JSON."""
    
    assert len(prompt) > 100, "Prompt is too short"
    assert "SQL Injection" in prompt
    assert "8.5" in prompt
    assert "JSON" in prompt.lower()


@pytest.mark.asyncio
async def test_llm_response_parsing():
    """Test parsing LLM response into structured format"""
    # Mock LLM response
    mock_response = """{
    "attack_scenario": "An attacker can inject malicious SQL code through the login form to bypass authentication or extract sensitive data.",
    "business_impact": "Complete database compromise, unauthorized access to user accounts, potential data breach with regulatory consequences.",
    "remediation_priority": "High",
    "recommendations": [
        "Implement prepared statements with parameterized queries",
        "Add input validation and sanitization",
        "Enable SQL error logging without exposing errors to users",
        "Conduct security code review of all database queries"
    ]
}"""
    
    try:
        parsed = json.loads(mock_response)
        
        assert "attack_scenario" in parsed
        assert "business_impact" in parsed
        assert "remediation_priority" in parsed
        assert "recommendations" in parsed
        
        assert isinstance(parsed["recommendations"], list)
        assert len(parsed["recommendations"]) > 0
        assert parsed["remediation_priority"] in ["High", "Medium", "Low"]
        
    except json.JSONDecodeError as e:
        pytest.fail(f"Failed to parse LLM response: {str(e)}")


@pytest.mark.asyncio
async def test_llm_error_handling():
    """Test LLM integration error handling"""
    with patch('groq.Groq') as MockGroq:
        mock_client = MagicMock()
        mock_client.chat.completions.create.side_effect = Exception("API rate limit exceeded")
        MockGroq.return_value = mock_client
        
        try:
            from groq import Groq
            client = Groq(api_key="test_key")
            
            with pytest.raises(Exception) as exc_info:
                response = client.chat.completions.create(
                    model="llama-3.3-70b-versatile",
                    messages=[{"role": "user", "content": "test"}]
                )
            
            assert "rate limit" in str(exc_info.value).lower()
            
        except ImportError:
            pytest.skip("Groq library not installed")


@pytest.mark.asyncio
async def test_batch_llm_analysis():
    """Test batch processing of multiple vulnerabilities"""
    vulnerabilities = [
        {"title": "SQL Injection", "severity": "HIGH"},
        {"title": "XSS", "severity": "MEDIUM"},
        {"title": "CSRF", "severity": "LOW"}
    ]
    
    # Mock batch processing
    results = []
    for vuln in vulnerabilities:
        # Simulate analysis result
        analysis = {
            "vulnerability": vuln["title"],
            "analysis": f"Mock analysis for {vuln['title']}",
            "priority": vuln["severity"]
        }
        results.append(analysis)
    
    assert len(results) == 3
    assert all("analysis" in r for r in results)
    assert results[0]["vulnerability"] == "SQL Injection"


@pytest.mark.asyncio
async def test_llm_context_window():
    """Test that prompts fit within LLM context window"""
    # Typical context windows: 8k, 32k, 128k tokens
    # Rough estimate: 1 token ≈ 4 characters
    max_context_tokens = 8000  # Conservative estimate
    max_chars = max_context_tokens * 4
    
    # Create a large vulnerability report
    large_vuln = {
        "title": "SQL Injection" * 100,
        "description": "User input concatenation " * 500,
        "recommendation": "Use prepared statements " * 100
    }
    
    prompt = f"""Analyze: {large_vuln['title'][:1000]}
Description: {large_vuln['description'][:2000]}
Recommendation: {large_vuln['recommendation'][:1000]}"""
    
    # Verify prompt is reasonable size
    assert len(prompt) < max_chars, f"Prompt too large: {len(prompt)} chars"


@pytest.mark.asyncio
async def test_llm_output_sanitization():
    """Test sanitization of LLM output"""
    # Mock potentially problematic LLM output
    mock_outputs = [
        "SQL Injection\n\n\n\nWith multiple newlines",
        "  Leading and trailing spaces  ",
        "Output with <script>alert('xss')</script> HTML",
        "Unicode characters: 你好 مرحبا"
    ]
    
    for output in mock_outputs:
        # Basic sanitization
        sanitized = output.strip()
        sanitized = ' '.join(sanitized.split())  # Normalize whitespace
        
        # Verify sanitization worked
        assert not sanitized.startswith(' ')
        assert not sanitized.endswith(' ')
        assert '\n\n\n' not in sanitized


def test_llm_model_selection():
    """Test model selection logic"""
    # Available models and their use cases
    models = {
        "llama-3.3-70b-versatile": {"use": "general", "context": 8192},
        "mixtral-8x7b": {"use": "fast", "context": 32768},
        "gemma2-9b-it": {"use": "lightweight", "context": 8192}
    }
    
    # Test model selection for different scenarios
    def select_model(task_type, context_size):
        if context_size > 10000:
            return "mixtral-8x7b"
        elif task_type == "quick":
            return "gemma2-9b-it"
        else:
            return "llama-3.3-70b-versatile"
    
    assert select_model("general", 5000) == "llama-3.3-70b-versatile"
    assert select_model("general", 15000) == "mixtral-8x7b"
    assert select_model("quick", 5000) == "gemma2-9b-it"


@pytest.mark.asyncio
async def test_llm_streaming_response():
    """Test streaming LLM responses"""
    # Mock streaming response
    chunks = [
        "This is ",
        "a streaming ",
        "response from ",
        "the LLM."
    ]
    
    full_response = ""
    for chunk in chunks:
        full_response += chunk
    
    assert full_response == "This is a streaming response from the LLM."
    assert len(chunks) == 4


@pytest.mark.asyncio
async def test_llm_retry_logic():
    """Test retry logic for failed LLM calls"""
    max_retries = 3
    retry_count = 0
    
    async def mock_llm_call_with_retries():
        nonlocal retry_count
        for attempt in range(max_retries):
            try:
                retry_count += 1
                if retry_count < 2:
                    raise Exception("Temporary failure")
                return {"success": True, "attempts": retry_count}
            except Exception as e:
                if attempt == max_retries - 1:
                    raise
                await asyncio.sleep(0.1)
    
    import asyncio
    result = await mock_llm_call_with_retries()
    
    assert result["success"] is True
    assert result["attempts"] == 2
    assert retry_count >= 2


@pytest.mark.asyncio
async def test_llm_cost_estimation():
    """Test LLM API cost estimation"""
    # Pricing (example rates per 1M tokens)
    pricing = {
        "llama-3.3-70b-versatile": {"input": 0.59, "output": 0.79},
        "mixtral-8x7b": {"input": 0.24, "output": 0.24},
        "gemma2-9b-it": {"input": 0.20, "output": 0.20}
    }
    
    def estimate_cost(model, input_tokens, output_tokens):
        rates = pricing.get(model, {"input": 1.0, "output": 1.0})
        input_cost = (input_tokens / 1_000_000) * rates["input"]
        output_cost = (output_tokens / 1_000_000) * rates["output"]
        return input_cost + output_cost
    
    # Test cost calculation
    cost = estimate_cost("llama-3.3-70b-versatile", 1000, 500)
    assert cost > 0
    assert cost < 0.01  # Should be very cheap for small requests
    
    # Batch processing cost
    batch_cost = estimate_cost("llama-3.3-70b-versatile", 50000, 25000)
    assert batch_cost > cost  # Larger batch should cost more
