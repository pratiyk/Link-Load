"""Test script to verify scanner initialization."""
import asyncio
import sys
import os
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent))

from app.core.config import settings
from app.services.scanners.nuclei_scanner import NucleiScanner, NucleiScannerConfig
from app.services.scanners.wapiti_scanner import WapitiScanner, WapitiScannerConfig
from app.services.scanners.zap_scanner import OWASPZAPScanner, ZAPScannerConfig


async def test_scanners():
    """Test scanner initialization."""
    
    print("=" * 60)
    print("Testing Scanner Initialization")
    print("=" * 60)
    
    # Test Nuclei
    print("\n1. Testing Nuclei Scanner...")
    print(f"   Binary path: {settings.NUCLEI_BINARY_PATH}")
    nuclei_config = NucleiScannerConfig(
        binary_path=settings.NUCLEI_BINARY_PATH or "nuclei"
    )
    nuclei_scanner = NucleiScanner(nuclei_config)
    nuclei_result = await nuclei_scanner.initialize()
    print(f"   ✓ Nuclei initialized: {nuclei_result}")
    
    # Test Wapiti
    print("\n2. Testing Wapiti Scanner...")
    print(f"   Binary path: {settings.WAPITI_BINARY_PATH}")
    wapiti_config = WapitiScannerConfig(
        binary_path=settings.WAPITI_BINARY_PATH or "wapiti"
    )
    wapiti_scanner = WapitiScanner(wapiti_config)
    wapiti_result = await wapiti_scanner.initialize()
    print(f"   ✓ Wapiti initialized: {wapiti_result}")
    
    # Test ZAP
    print("\n3. Testing OWASP ZAP Scanner...")
    print(f"   Base URL: {settings.ZAP_BASE_URL}")
    if settings.ZAP_BASE_URL:
        try:
            host = settings.ZAP_BASE_URL.split("://")[1].split(":")[0]
            port = int(settings.ZAP_BASE_URL.split(":")[-1])
        except:
            host = "127.0.0.1"
            port = 8080
    else:
        host = "127.0.0.1"
        port = 8080
    
    zap_config = ZAPScannerConfig(
        api_key=settings.ZAP_API_KEY or "",
        host=host,
        port=port
    )
    zap_scanner = OWASPZAPScanner(zap_config)
    zap_result = await zap_scanner.initialize()
    print(f"   ✓ ZAP initialized: {zap_result}")
    if not zap_result:
        print(f"   ℹ ZAP is expected to fail if not running at {host}:{port}")
    
    # Test OpenAI
    print("\n4. Testing OpenAI Integration...")
    print(f"   API Key configured: {'Yes' if settings.OPENAI_API_KEY else 'No'}")
    if settings.OPENAI_API_KEY:
        print(f"   API Key prefix: {settings.OPENAI_API_KEY[:20]}...")
        
        from app.services.llm_service import llm_service
        print(f"   ✓ LLM service initialized: {llm_service._provider.__class__.__name__}")
    else:
        print("   ⚠ OpenAI API key not configured")
    
    print("\n" + "=" * 60)
    print("Scanner Initialization Test Complete")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(test_scanners())
