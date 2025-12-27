import requests
import openai

def get_ibm_breach_cost(industry, region):
    # Example: Replace with real IBM API endpoint and authentication
    # IBM does not provide a public API, so use their published dataset or a paid API if available
    # Here, we use a static mapping for demonstration
    ibm_costs = {
        ('financial', 'India'): 179000000,
        ('healthcare', 'India'): 160000000,
        ('general', 'India'): 5000000,
    }
    return ibm_costs.get((industry.lower(), region), 5000000)

def get_cve_remediation_cost(cve_id):
    # CVE Details API (public, no key required for basic queries)
    url = f"https://cve.circl.lu/api/cve/{cve_id}"
    try:
        resp = requests.get(url, timeout=10)
        data = resp.json()
        severity = data.get('cvss', 5)
        # Example logic: severity × ₹10,000
        return severity * 10000
    except Exception:
        return 12000

def get_llm_estimate(vuln_title, vuln_desc, openai_api_key=None, groq_api_key=None, provider="openai"):
    prompt = f"Estimate remediation cost and potential loss for vulnerability: {vuln_title}. Description: {vuln_desc}. Provide numbers in INR."
    if provider == "groq" and groq_api_key:
        import requests
        url = "https://api.groq.com/v1/chat/completions"
        headers = {"Authorization": f"Bearer {groq_api_key}", "Content-Type": "application/json"}
        payload = {
            "model": "mixtral-8x7b-32768",
            "messages": [{"role": "user", "content": prompt}]
        }
        resp = requests.post(url, json=payload, headers=headers, timeout=20)
        data = resp.json()
        return data['choices'][0]['message']['content']
    elif provider == "openai" and openai_api_key:
        import openai
        openai.api_key = openai_api_key
        # For OpenAI v1, use openai.chat.completions.create
        response = openai.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": prompt}]
        )
        return response.choices[0].message.content
    else:
        return "No LLM provider or API key configured."

# API Key Locations:
# IBM: If you use a paid IBM API, get the key from IBM Cloud dashboard (https://cloud.ibm.com/apidocs)
# CVE Details: Public API, no key required for basic queries
# OpenAI: Get your API key from https://platform.openai.com/account/api-keys
