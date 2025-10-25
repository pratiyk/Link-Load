"""Demo script showing OpenAI integration working with sample vulnerabilities."""
import asyncio
import sys
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent))

from app.services.llm_service import llm_service


async def demo_ai_analysis():
    """Demonstrate AI-powered vulnerability analysis."""
    
    print("\n" + "=" * 70)
    print(" LinkLoad AI-Powered Vulnerability Analysis Demo")
    print("=" * 70)
    
    # Sample vulnerabilities (simulating scanner output)
    sample_vulnerabilities = [
        {
            "title": "SQL Injection in Login Form",
            "severity": "critical",
            "cvss_score": 9.8,
            "description": "The login endpoint does not properly sanitize user input, allowing SQL injection attacks.",
            "location": "https://example.com/api/auth/login",
            "parameter": "username",
            "evidence": "' OR '1'='1 returns successful login"
        },
        {
            "title": "Cross-Site Scripting (XSS)",
            "severity": "high",
            "cvss_score": 7.5,
            "description": "Reflected XSS vulnerability in search functionality",
            "location": "https://example.com/search",
            "parameter": "q",
            "evidence": "<script>alert(1)</script> executed in response"
        },
        {
            "title": "Missing Security Headers",
            "severity": "medium",
            "cvss_score": 5.3,
            "description": "Application is missing critical security headers like X-Frame-Options, CSP",
            "location": "https://example.com",
            "parameter": "N/A",
            "evidence": "No X-Frame-Options, Content-Security-Policy, or X-Content-Type-Options headers"
        },
        {
            "title": "Weak Password Policy",
            "severity": "medium",
            "cvss_score": 4.5,
            "description": "Password requirements are too weak, allowing easily guessable passwords",
            "location": "https://example.com/register",
            "parameter": "password",
            "evidence": "Accepts passwords like '123456' and 'password'"
        },
        {
            "title": "Information Disclosure",
            "severity": "low",
            "cvss_score": 3.7,
            "description": "Server version exposed in HTTP headers",
            "location": "https://example.com",
            "parameter": "N/A",
            "evidence": "Server: Apache/2.4.41 (Ubuntu)"
        }
    ]
    
    print(f"\n📊 Analyzing {len(sample_vulnerabilities)} sample vulnerabilities...")
    print(f"Target: https://example.com")
    print(f"Business Context: E-commerce platform handling customer data and payments")
    
    # Perform AI analysis
    print("\n🤖 Calling OpenAI GPT-4 for analysis...")
    print("   (This may take 10-20 seconds...)")
    
    try:
        result = await llm_service.analyze_vulnerabilities(
            vulnerabilities=sample_vulnerabilities,
            target_url="https://example.com",
            business_context="E-commerce platform handling customer data, payment processing, and personal information"
        )
        
        # Display results
        print("\n" + "=" * 70)
        print(" AI Analysis Results")
        print("=" * 70)
        
        # Executive Summary
        if "executive_summary" in result:
            print("\n📋 EXECUTIVE SUMMARY")
            print("-" * 70)
            print(result["executive_summary"])
        
        # Detailed vulnerability analysis
        if "vulnerabilities" in result and result["vulnerabilities"]:
            print("\n\n🔍 DETAILED VULNERABILITY ANALYSIS")
            print("-" * 70)
            
            for i, vuln in enumerate(result["vulnerabilities"], 1):
                print(f"\n{i}. {vuln.get('title', 'Unknown')}")
                print(f"   Priority: {vuln.get('priority', 'N/A')}/10")
                print(f"   Fix Complexity: {vuln.get('fix_complexity', 'N/A').upper()}")
                
                # Business impact
                if "business_impact" in vuln:
                    print(f"\n   💼 Business Impact:")
                    print(f"      {vuln['business_impact']}")
                
                # Remediation steps
                if "remediation" in vuln and vuln["remediation"]:
                    print(f"\n   ✅ Remediation Steps:")
                    for j, step in enumerate(vuln["remediation"], 1):
                        print(f"      {j}. {step}")
                
                print()
        
        # Generate executive summary
        print("\n" + "=" * 70)
        print(" Executive Summary for Leadership")
        print("=" * 70)
        
        summary = await llm_service.generate_executive_summary(
            vulnerabilities=sample_vulnerabilities,
            risk_score=7.8,
            risk_level="High"
        )
        
        print(f"\n{summary}")
        
        print("\n" + "=" * 70)
        print("✅ Demo Complete!")
        print("=" * 70)
        print("\n💡 Key Capabilities Demonstrated:")
        print("   • AI-powered vulnerability analysis using GPT-4")
        print("   • Business impact assessment")
        print("   • Prioritized remediation recommendations")
        print("   • Executive-level summaries")
        print("   • Context-aware security guidance")
        
        print("\n🚀 Next Steps:")
        print("   1. Install scanner tools (see SCANNER_TOOLS_INSTALLATION.md)")
        print("   2. Run real scans against test targets")
        print("   3. Get AI analysis of actual vulnerabilities")
        
        return True
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        print("\nPossible issues:")
        print("   • OpenAI API key not configured")
        print("   • Network connectivity issues")
        print("   • Rate limiting or quota exceeded")
        return False


if __name__ == "__main__":
    success = asyncio.run(demo_ai_analysis())
    sys.exit(0 if success else 1)
