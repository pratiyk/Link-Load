"""
Unified Threat Intelligence Service
Aggregates data from multiple threat intelligence APIs:
- VirusTotal (VT_API_KEY)
- Google Safe Browsing (GSB_API_KEY)
- AbuseIPDB (ABUSEIPDB_API_KEY)
- Shodan (SHODAN_API_KEY)
- NVD (NVD_API_KEY)
- Leak Lookup (LEAK_LOOKUP_API_KEY)
- SecurityTrails (SECURITYTRAILS_API_KEY)
- Vulners (VULNERS_API_KEY)
"""
import os
import asyncio
import logging
import socket
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
from urllib.parse import urlparse
import httpx
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

# API Keys from environment
VT_API_KEY = os.getenv("VT_API_KEY")
GSB_API_KEY = os.getenv("GSB_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
NVD_API_KEY = os.getenv("NVD_API_KEY")
LEAK_LOOKUP_API_KEY = os.getenv("LEAK_LOOKUP_API_KEY")
SECURITYTRAILS_API_KEY = os.getenv("SECURITYTRAILS_API_KEY")
VULNERS_API_KEY = os.getenv("VULNERS_API_KEY")


class UnifiedThreatIntelService:
    """
    Unified service for gathering threat intelligence from multiple sources.
    Used during security scans to enrich vulnerability data with real-time threat context.
    """

    def __init__(self):
        self.timeout = 15  # seconds per API call
        self._cache = {}  # Simple in-memory cache for repeat queries

    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL."""
        try:
            parsed = urlparse(url)
            return parsed.netloc or parsed.path.split('/')[0]
        except Exception:
            return url

    def _resolve_ip(self, domain: str) -> Optional[str]:
        """Resolve domain to IP address."""
        try:
            return socket.gethostbyname(domain)
        except Exception:
            return None

    async def gather_threat_intel(self, target_url: str) -> Dict[str, Any]:
        """
        Gather comprehensive threat intelligence for a target URL.
        Called at the start of each scan to enrich results.
        
        Returns:
            Dict containing threat data from all available sources
        """
        domain = self._extract_domain(target_url)
        ip_address = self._resolve_ip(domain)
        
        logger.info(f"[INTEL] Gathering threat intelligence for domain={domain}, ip={ip_address}")
        
        # Check cache first
        cache_key = f"{domain}_{ip_address}"
        if cache_key in self._cache:
            cache_entry = self._cache[cache_key]
            # Cache for 1 hour
            if (datetime.now(timezone.utc) - cache_entry['timestamp']).seconds < 3600:
                logger.info("[INTEL] Returning cached threat intel")
                return cache_entry['data']
        
        # Gather data from all sources concurrently
        async def _noop():
            return None
        
        tasks = [
            self._get_virustotal_intel(domain),
            self._get_google_safe_browsing(target_url),
            self._get_abuseipdb_intel(ip_address) if ip_address else _noop(),
            self._get_shodan_intel(ip_address) if ip_address else _noop(),
            self._get_securitytrails_intel(domain),
            self._get_leak_lookup_intel(domain),
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        vt_data, gsb_data, abuse_data, shodan_data, sectrails_data, leak_data = results
        
        # Handle exceptions
        vt_data = vt_data if not isinstance(vt_data, Exception) else None
        gsb_data = gsb_data if not isinstance(gsb_data, Exception) else None
        abuse_data = abuse_data if not isinstance(abuse_data, Exception) else None
        shodan_data = shodan_data if not isinstance(shodan_data, Exception) else None
        sectrails_data = sectrails_data if not isinstance(sectrails_data, Exception) else None
        leak_data = leak_data if not isinstance(leak_data, Exception) else None
        
        # Compile threat intelligence report
        intel_report = {
            "target": {
                "url": target_url,
                "domain": domain,
                "ip_address": ip_address,
                "resolved_at": datetime.now(timezone.utc).isoformat()
            },
            "reputation": self._calculate_reputation_score(vt_data, abuse_data, gsb_data),
            "virustotal": vt_data,
            "google_safe_browsing": gsb_data,
            "abuseipdb": abuse_data,
            "shodan": shodan_data,
            "securitytrails": sectrails_data,
            "leak_lookup": leak_data,
            "risk_indicators": self._extract_risk_indicators(
                vt_data, gsb_data, abuse_data, shodan_data, sectrails_data, leak_data
            ),
            "data_sources_queried": self._count_successful_sources(
                vt_data, gsb_data, abuse_data, shodan_data, sectrails_data, leak_data
            ),
            "collected_at": datetime.now(timezone.utc).isoformat()
        }
        
        # Cache the result
        self._cache[cache_key] = {
            'timestamp': datetime.now(timezone.utc),
            'data': intel_report
        }
        
        logger.info(f"[INTEL] Collected intel from {intel_report['data_sources_queried']} sources")
        return intel_report

    async def _get_virustotal_intel(self, domain: str) -> Optional[Dict[str, Any]]:
        """Query VirusTotal for domain reputation."""
        if not VT_API_KEY:
            logger.warning("[INTEL] VirusTotal API key not configured")
            return None
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                # Get domain report
                response = await client.get(
                    f"https://www.virustotal.com/api/v3/domains/{domain}",
                    headers={"x-apikey": VT_API_KEY}
                )
                
                if response.status_code == 200:
                    data = response.json()
                    attributes = data.get("data", {}).get("attributes", {})
                    last_analysis = attributes.get("last_analysis_stats", {})
                    
                    return {
                        "malicious": last_analysis.get("malicious", 0),
                        "suspicious": last_analysis.get("suspicious", 0),
                        "harmless": last_analysis.get("harmless", 0),
                        "undetected": last_analysis.get("undetected", 0),
                        "timeout": last_analysis.get("timeout", 0),
                        "total_engines": sum(last_analysis.values()) if last_analysis else 0,
                        "reputation_score": attributes.get("reputation", 0),
                        "categories": attributes.get("categories", {}),
                        "registrar": attributes.get("registrar"),
                        "creation_date": attributes.get("creation_date"),
                        "whois": attributes.get("whois", "")[:500] if attributes.get("whois") else None,
                        "last_dns_records": attributes.get("last_dns_records", [])[:5],
                        "popularity_ranks": attributes.get("popularity_ranks", {}),
                        "detected_urls": len(attributes.get("last_https_certificate", {}).get("subject", {}).get("CN", [])) if attributes.get("last_https_certificate") else 0
                    }
                elif response.status_code == 404:
                    logger.info(f"[INTEL] Domain {domain} not found in VirusTotal")
                    return {"status": "not_found", "message": "Domain not in VirusTotal database"}
                else:
                    logger.warning(f"[INTEL] VirusTotal API error: {response.status_code}")
                    return None
        except Exception as e:
            logger.error(f"[INTEL] VirusTotal query failed: {e}")
            return None

    async def _get_google_safe_browsing(self, url: str) -> Optional[Dict[str, Any]]:
        """Check URL against Google Safe Browsing API."""
        if not GSB_API_KEY:
            logger.warning("[INTEL] Google Safe Browsing API key not configured")
            return None
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}",
                    json={
                        "client": {
                            "clientId": "linkload-scanner",
                            "clientVersion": "1.0.0"
                        },
                        "threatInfo": {
                            "threatTypes": [
                                "MALWARE",
                                "SOCIAL_ENGINEERING",
                                "UNWANTED_SOFTWARE",
                                "POTENTIALLY_HARMFUL_APPLICATION"
                            ],
                            "platformTypes": ["ANY_PLATFORM"],
                            "threatEntryTypes": ["URL"],
                            "threatEntries": [{"url": url}]
                        }
                    }
                )
                
                if response.status_code == 200:
                    data = response.json()
                    matches = data.get("matches", [])
                    
                    if matches:
                        return {
                            "is_flagged": True,
                            "threat_types": [m.get("threatType") for m in matches],
                            "platform_types": [m.get("platformType") for m in matches],
                            "threat_count": len(matches),
                            "matches": matches
                        }
                    else:
                        return {
                            "is_flagged": False,
                            "threat_types": [],
                            "message": "No threats detected by Google Safe Browsing"
                        }
                else:
                    logger.warning(f"[INTEL] Google Safe Browsing API error: {response.status_code}")
                    return None
        except Exception as e:
            logger.error(f"[INTEL] Google Safe Browsing query failed: {e}")
            return None

    async def _get_abuseipdb_intel(self, ip: str) -> Optional[Dict[str, Any]]:
        """Query AbuseIPDB for IP reputation."""
        if not ip or not ABUSEIPDB_API_KEY:
            return None
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers={
                        "Key": ABUSEIPDB_API_KEY,
                        "Accept": "application/json"
                    },
                    params={
                        "ipAddress": ip,
                        "maxAgeInDays": 90,
                        "verbose": ""
                    }
                )
                
                if response.status_code == 200:
                    data = response.json().get("data", {})
                    return {
                        "ip_address": data.get("ipAddress"),
                        "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                        "is_public": data.get("isPublic", True),
                        "is_whitelisted": data.get("isWhitelisted", False),
                        "country_code": data.get("countryCode"),
                        "isp": data.get("isp"),
                        "domain": data.get("domain"),
                        "total_reports": data.get("totalReports", 0),
                        "num_distinct_users": data.get("numDistinctUsers", 0),
                        "last_reported_at": data.get("lastReportedAt"),
                        "usage_type": data.get("usageType"),
                        "hostnames": data.get("hostnames", [])
                    }
                else:
                    logger.warning(f"[INTEL] AbuseIPDB API error: {response.status_code}")
                    return None
        except Exception as e:
            logger.error(f"[INTEL] AbuseIPDB query failed: {e}")
            return None

    async def _get_shodan_intel(self, ip: str) -> Optional[Dict[str, Any]]:
        """Query Shodan for host information."""
        if not ip or not SHODAN_API_KEY:
            return None
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    f"https://api.shodan.io/shodan/host/{ip}",
                    params={"key": SHODAN_API_KEY}
                )
                
                if response.status_code == 200:
                    data = response.json()
                    
                    # Extract services info
                    services = []
                    vulns = []
                    for item in data.get("data", []):
                        service_info = {
                            "port": item.get("port"),
                            "transport": item.get("transport"),
                            "product": item.get("product"),
                            "version": item.get("version"),
                            "banner": (item.get("data") or "")[:200]
                        }
                        services.append(service_info)
                        
                        # Extract vulnerabilities
                        if item.get("vulns"):
                            for vuln_id in item.get("vulns", {}):
                                vulns.append({
                                    "cve_id": vuln_id,
                                    "port": item.get("port"),
                                    "details": item["vulns"][vuln_id] if isinstance(item["vulns"], dict) else None
                                })
                    
                    return {
                        "ip": data.get("ip_str"),
                        "ports": data.get("ports", []),
                        "hostnames": data.get("hostnames", []),
                        "country": data.get("country_name"),
                        "city": data.get("city"),
                        "org": data.get("org"),
                        "isp": data.get("isp"),
                        "asn": data.get("asn"),
                        "os": data.get("os"),
                        "services": services[:10],  # Top 10 services
                        "vulnerabilities": vulns[:20],  # Top 20 vulns
                        "vuln_count": len(vulns),
                        "open_ports_count": len(data.get("ports", [])),
                        "tags": data.get("tags", []),
                        "last_update": data.get("last_update")
                    }
                elif response.status_code == 404:
                    return {"status": "not_found", "message": "IP not in Shodan database"}
                else:
                    logger.warning(f"[INTEL] Shodan API error: {response.status_code}")
                    return None
        except Exception as e:
            logger.error(f"[INTEL] Shodan query failed: {e}")
            return None

    async def _get_securitytrails_intel(self, domain: str) -> Optional[Dict[str, Any]]:
        """Query SecurityTrails for domain intelligence."""
        if not SECURITYTRAILS_API_KEY:
            logger.warning("[INTEL] SecurityTrails API key not configured")
            return None
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                # Get domain info
                response = await client.get(
                    f"https://api.securitytrails.com/v1/domain/{domain}",
                    headers={"APIKEY": SECURITYTRAILS_API_KEY}
                )
                
                if response.status_code == 200:
                    data = response.json()
                    
                    # Also get subdomains
                    subdomain_response = await client.get(
                        f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
                        headers={"APIKEY": SECURITYTRAILS_API_KEY}
                    )
                    
                    subdomains = []
                    if subdomain_response.status_code == 200:
                        subdomains = subdomain_response.json().get("subdomains", [])[:20]
                    
                    # Get DNS history
                    dns_history_response = await client.get(
                        f"https://api.securitytrails.com/v1/history/{domain}/dns/a",
                        headers={"APIKEY": SECURITYTRAILS_API_KEY}
                    )
                    
                    dns_history = []
                    if dns_history_response.status_code == 200:
                        records = dns_history_response.json().get("records", [])
                        dns_history = records[:10]  # Last 10 records
                    
                    current_dns = data.get("current_dns", {})
                    
                    return {
                        "hostname": data.get("hostname"),
                        "apex_domain": data.get("apex_domain"),
                        "alexa_rank": data.get("alexa_rank"),
                        "current_dns": {
                            "a_records": [r.get("ip") for r in current_dns.get("a", {}).get("values", [])],
                            "aaaa_records": [r.get("ipv6") for r in current_dns.get("aaaa", {}).get("values", [])],
                            "mx_records": [r.get("host") for r in current_dns.get("mx", {}).get("values", [])],
                            "ns_records": [r.get("nameserver") for r in current_dns.get("ns", {}).get("values", [])],
                            "txt_records": [r.get("value") for r in current_dns.get("txt", {}).get("values", [])][:5]
                        },
                        "subdomains": subdomains,
                        "subdomain_count": len(subdomains),
                        "dns_history": dns_history,
                        "dns_changes": len(dns_history)
                    }
                elif response.status_code == 404:
                    return {"status": "not_found", "message": "Domain not found in SecurityTrails"}
                else:
                    logger.warning(f"[INTEL] SecurityTrails API error: {response.status_code}")
                    return None
        except Exception as e:
            logger.error(f"[INTEL] SecurityTrails query failed: {e}")
            return None

    async def _get_leak_lookup_intel(self, domain: str) -> Optional[Dict[str, Any]]:
        """Query LeakLookup for data breach information."""
        if not LEAK_LOOKUP_API_KEY:
            logger.warning("[INTEL] Leak Lookup API key not configured")
            return None
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    "https://leak-lookup.com/api/search",
                    headers={"Content-Type": "application/json"},
                    json={
                        "key": LEAK_LOOKUP_API_KEY,
                        "type": "domain",
                        "query": domain
                    }
                )
                
                if response.status_code == 200:
                    data = response.json()
                    
                    if data.get("error") == "false" or data.get("error") is False:
                        results = data.get("message", [])
                        
                        # Count unique breaches
                        breach_sources = set()
                        total_records = 0
                        
                        if isinstance(results, dict):
                            for source, records in results.items():
                                breach_sources.add(source)
                                total_records += len(records) if isinstance(records, list) else 1
                        
                        return {
                            "domain_searched": domain,
                            "breaches_found": len(breach_sources),
                            "breach_sources": list(breach_sources)[:10],
                            "total_leaked_records": total_records,
                            "has_breaches": total_records > 0
                        }
                    else:
                        return {
                            "domain_searched": domain,
                            "breaches_found": 0,
                            "has_breaches": False,
                            "message": "No breach data found"
                        }
                else:
                    logger.warning(f"[INTEL] Leak Lookup API error: {response.status_code}")
                    return None
        except Exception as e:
            logger.error(f"[INTEL] Leak Lookup query failed: {e}")
            return None

    async def enrich_vulnerabilities_with_nvd(
        self,
        vulnerabilities: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Enrich vulnerabilities with NVD CVE data."""
        if not NVD_API_KEY:
            logger.warning("[INTEL] NVD API key not configured")
            return vulnerabilities
        
        enriched = []
        for vuln in vulnerabilities:
            cve_id = vuln.get("cve_id")
            
            if cve_id and cve_id.startswith("CVE-"):
                nvd_data = await self._get_nvd_cve_data(cve_id)
                if nvd_data:
                    vuln["nvd_data"] = nvd_data
                    # Update CVSS score if available
                    if nvd_data.get("cvss_v3_score"):
                        vuln["cvss_score"] = nvd_data["cvss_v3_score"]
            
            enriched.append(vuln)
        
        return enriched

    async def _get_nvd_cve_data(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Query NVD for specific CVE data."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    f"https://services.nvd.nist.gov/rest/json/cves/2.0",
                    params={"cveId": cve_id},
                    headers={"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
                )
                
                if response.status_code == 200:
                    data = response.json()
                    vulnerabilities = data.get("vulnerabilities", [])
                    
                    if vulnerabilities:
                        cve_data = vulnerabilities[0].get("cve", {})
                        metrics = cve_data.get("metrics", {})
                        
                        # Get CVSS v3 score
                        cvss_v3 = None
                        cvss_v3_data = metrics.get("cvssMetricV31", []) or metrics.get("cvssMetricV30", [])
                        if cvss_v3_data:
                            cvss_v3 = cvss_v3_data[0].get("cvssData", {})
                        
                        # Get CVSS v2 score as fallback
                        cvss_v2 = None
                        cvss_v2_data = metrics.get("cvssMetricV2", [])
                        if cvss_v2_data:
                            cvss_v2 = cvss_v2_data[0].get("cvssData", {})
                        
                        descriptions = cve_data.get("descriptions", [])
                        description = next(
                            (d.get("value") for d in descriptions if d.get("lang") == "en"),
                            descriptions[0].get("value") if descriptions else ""
                        )
                        
                        references = [
                            ref.get("url") for ref in cve_data.get("references", [])[:5]
                        ]
                        
                        weaknesses = []
                        for weakness in cve_data.get("weaknesses", []):
                            for desc in weakness.get("description", []):
                                if desc.get("lang") == "en":
                                    weaknesses.append(desc.get("value"))
                        
                        return {
                            "cve_id": cve_id,
                            "description": description[:500],
                            "cvss_v3_score": cvss_v3.get("baseScore") if cvss_v3 else None,
                            "cvss_v3_severity": cvss_v3.get("baseSeverity") if cvss_v3 else None,
                            "cvss_v3_vector": cvss_v3.get("vectorString") if cvss_v3 else None,
                            "cvss_v2_score": cvss_v2.get("baseScore") if cvss_v2 else None,
                            "weaknesses": weaknesses[:3],
                            "references": references,
                            "published_date": cve_data.get("published"),
                            "last_modified": cve_data.get("lastModified")
                        }
                    return None
                else:
                    return None
        except Exception as e:
            logger.error(f"[INTEL] NVD query failed for {cve_id}: {e}")
            return None

    async def search_vulners(self, query: str) -> Optional[Dict[str, Any]]:
        """Search Vulners for exploit and vulnerability information."""
        if not VULNERS_API_KEY:
            logger.warning("[INTEL] Vulners API key not configured")
            return None
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    "https://vulners.com/api/v3/search/lucene/",
                    json={
                        "query": query,
                        "apiKey": VULNERS_API_KEY,
                        "size": 10
                    }
                )
                
                if response.status_code == 200:
                    data = response.json()
                    
                    if data.get("result") == "OK":
                        search_results = data.get("data", {}).get("search", [])
                        
                        exploits = []
                        vulnerabilities = []
                        
                        for result in search_results:
                            item = result.get("_source", {})
                            item_type = item.get("type", "")
                            
                            parsed_item = {
                                "id": item.get("id"),
                                "title": item.get("title"),
                                "type": item_type,
                                "cvss_score": item.get("cvss", {}).get("score") if isinstance(item.get("cvss"), dict) else item.get("cvss"),
                                "published": item.get("published"),
                                "href": item.get("href"),
                                "description": (item.get("description") or "")[:300]
                            }
                            
                            if "exploit" in item_type.lower():
                                exploits.append(parsed_item)
                            else:
                                vulnerabilities.append(parsed_item)
                        
                        return {
                            "query": query,
                            "total_results": data.get("data", {}).get("total", 0),
                            "exploits": exploits,
                            "exploit_count": len(exploits),
                            "vulnerabilities": vulnerabilities,
                            "vulnerability_count": len(vulnerabilities)
                        }
                    return None
                else:
                    logger.warning(f"[INTEL] Vulners API error: {response.status_code}")
                    return None
        except Exception as e:
            logger.error(f"[INTEL] Vulners query failed: {e}")
            return None

    def _calculate_reputation_score(
        self,
        vt_data: Optional[Dict],
        abuse_data: Optional[Dict],
        gsb_data: Optional[Dict]
    ) -> Dict[str, Any]:
        """Calculate an overall reputation score from available intel."""
        score = 100  # Start with perfect score
        risk_level = "Low"
        factors = []
        
        # VirusTotal analysis
        if vt_data and not vt_data.get("status") == "not_found":
            malicious = vt_data.get("malicious", 0)
            suspicious = vt_data.get("suspicious", 0)
            total = vt_data.get("total_engines", 1) or 1
            
            vt_risk = ((malicious * 2 + suspicious) / total) * 100
            score -= vt_risk
            
            if malicious > 0:
                factors.append(f"VirusTotal: {malicious} engines detected as malicious")
                risk_level = "Critical" if malicious > 5 else "High"
            elif suspicious > 0:
                factors.append(f"VirusTotal: {suspicious} engines flagged as suspicious")
                if risk_level == "Low":
                    risk_level = "Medium"
        
        # AbuseIPDB analysis
        if abuse_data and abuse_data.get("abuse_confidence_score"):
            abuse_score = abuse_data.get("abuse_confidence_score", 0)
            score -= abuse_score * 0.5
            
            if abuse_score > 75:
                factors.append(f"AbuseIPDB: {abuse_score}% abuse confidence")
                risk_level = "Critical"
            elif abuse_score > 50:
                factors.append(f"AbuseIPDB: {abuse_score}% abuse confidence")
                if risk_level not in ["Critical"]:
                    risk_level = "High"
            elif abuse_score > 25:
                factors.append(f"AbuseIPDB: {abuse_score}% abuse confidence")
                if risk_level not in ["Critical", "High"]:
                    risk_level = "Medium"
        
        # Google Safe Browsing
        if gsb_data and gsb_data.get("is_flagged"):
            score -= 50
            threats = gsb_data.get("threat_types", [])
            factors.append(f"Google Safe Browsing: Flagged for {', '.join(threats)}")
            risk_level = "Critical"
        
        return {
            "score": max(0, min(100, round(score))),
            "risk_level": risk_level,
            "factors": factors,
            "sources_checked": sum([
                1 if vt_data else 0,
                1 if abuse_data else 0,
                1 if gsb_data else 0
            ])
        }

    def _extract_risk_indicators(self, *sources) -> List[Dict[str, Any]]:
        """Extract key risk indicators from all sources."""
        indicators = []
        
        vt_data, gsb_data, abuse_data, shodan_data, sectrails_data, leak_data = sources
        
        # VirusTotal indicators
        if vt_data and vt_data.get("malicious", 0) > 0:
            indicators.append({
                "source": "VirusTotal",
                "type": "malicious_detection",
                "severity": "critical" if vt_data.get("malicious", 0) > 5 else "high",
                "details": f"{vt_data.get('malicious')} security vendors flagged this domain"
            })
        
        # Google Safe Browsing indicators
        if gsb_data and gsb_data.get("is_flagged"):
            indicators.append({
                "source": "Google Safe Browsing",
                "type": "threat_detected",
                "severity": "critical",
                "details": f"Flagged for: {', '.join(gsb_data.get('threat_types', []))}"
            })
        
        # AbuseIPDB indicators
        if abuse_data and abuse_data.get("abuse_confidence_score", 0) > 25:
            indicators.append({
                "source": "AbuseIPDB",
                "type": "abuse_reports",
                "severity": "high" if abuse_data.get("abuse_confidence_score", 0) > 50 else "medium",
                "details": f"{abuse_data.get('total_reports', 0)} abuse reports, {abuse_data.get('abuse_confidence_score')}% confidence"
            })
        
        # Shodan indicators
        if shodan_data and shodan_data.get("vuln_count", 0) > 0:
            indicators.append({
                "source": "Shodan",
                "type": "exposed_vulnerabilities",
                "severity": "high",
                "details": f"{shodan_data.get('vuln_count')} known vulnerabilities on {shodan_data.get('open_ports_count', 0)} open ports"
            })
        
        if shodan_data and shodan_data.get("open_ports_count", 0) > 10:
            indicators.append({
                "source": "Shodan",
                "type": "excessive_open_ports",
                "severity": "medium",
                "details": f"{shodan_data.get('open_ports_count')} open ports detected"
            })
        
        # SecurityTrails indicators
        if sectrails_data and sectrails_data.get("subdomain_count", 0) > 50:
            indicators.append({
                "source": "SecurityTrails",
                "type": "large_attack_surface",
                "severity": "medium",
                "details": f"{sectrails_data.get('subdomain_count')} subdomains detected"
            })
        
        # Leak Lookup indicators
        if leak_data and leak_data.get("has_breaches"):
            indicators.append({
                "source": "LeakLookup",
                "type": "data_breach",
                "severity": "high",
                "details": f"Found in {leak_data.get('breaches_found', 0)} data breaches"
            })
        
        return sorted(indicators, key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x.get("severity", "low"), 4))

    def _count_successful_sources(self, *sources) -> int:
        """Count how many sources returned data."""
        return sum(1 for s in sources if s and not (isinstance(s, dict) and s.get("status") == "not_found"))


# Singleton instance
unified_threat_intel = UnifiedThreatIntelService()
