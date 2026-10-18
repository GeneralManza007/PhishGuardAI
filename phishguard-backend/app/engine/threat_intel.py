# app/engine/threat_intel.py
import re
import os
import asyncio
import aiohttp
import logging
from typing import List, Dict, Any, Optional, Set
from datetime import datetime, timedelta
from abc import ABC, abstractmethod

from .models import Finding, Severity

# --- Logging ---
logger = logging.getLogger(__name__)

# --- Configuration ---
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", None)
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", None)

# --- Cache (simple in-memory, with TTL) ---
_cache = {}
CACHE_TTL = timedelta(hours=24)

def _get_cache(key: str) -> Optional[Dict]:
    if key in _cache:
        data, timestamp = _cache[key]
        if datetime.now() - timestamp < CACHE_TTL:
            return data
        del _cache[key]
    return None

def _set_cache(key: str, data: Dict):
    _cache[key] = (data, datetime.now())

# --- Base Provider ---
class ThreatIntelProvider(ABC):
    """Base class for threat intelligence providers."""
    
    @abstractmethod
    async def lookup(self, session: aiohttp.ClientSession, target: str) -> Dict[str, Any]:
        """
        Lookup a target (domain, IP, URL, hash, email) and return raw result.
        """
        pass
    
    def name(self) -> str:
        return self.__class__.__name__.replace("Provider", "")

# --- VirusTotal Provider ---
class VirusTotalProvider(ThreatIntelProvider):
    def __init__(self, api_key: str = VIRUSTOTAL_API_KEY):
        self.api_key = api_key
        self.enabled = bool(api_key)
    
    async def lookup(self, session: aiohttp.ClientSession, target: str) -> Dict[str, Any]:
        if not self.enabled:
            return {"available": False, "error": "No API key"}
        
        cache_key = f"virustotal_{target}"
        cached = _get_cache(cache_key)
        if cached:
            return cached
        
        # Determine type (IP or domain)
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        is_ip = bool(re.match(ip_pattern, target))
        endpoint = "ip_addresses" if is_ip else "domains"
        url = f"https://www.virustotal.com/api/v3/{endpoint}/{target}"
        headers = {"x-apikey": self.api_key}
        
        try:
            async with session.get(url, headers=headers, timeout=10) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    attributes = data['data']['attributes']
                    stats = attributes.get('last_analysis_stats', {})
                    result = {
                        "available": True,
                        "malicious": stats.get('malicious', 0),
                        "suspicious": stats.get('suspicious', 0),
                        "undetected": stats.get('undetected', 0),
                        "harmless": stats.get('harmless', 0),
                        "total": sum(stats.values()),
                        "is_malicious": stats.get('malicious', 0) > 0,
                    }
                    _set_cache(cache_key, result)
                    return result
                elif resp.status == 404:
                    result = {"available": True, "not_found": True}
                    _set_cache(cache_key, result)
                    return result
                else:
                    error_text = await resp.text()
                    logger.warning(f"VirusTotal error {resp.status}: {error_text[:200]}")
                    return {"available": False, "error": f"HTTP {resp.status}"}
        except Exception as e:
            logger.exception(f"VirusTotal lookup failed for {target}: {e}")
            return {"available": False, "error": str(e)}

# --- AbuseIPDB Provider ---
class AbuseIPDBProvider(ThreatIntelProvider):
    def __init__(self, api_key: str = ABUSEIPDB_API_KEY):
        self.api_key = api_key
        self.enabled = bool(api_key)
    
    async def lookup(self, session: aiohttp.ClientSession, target: str) -> Dict[str, Any]:
        if not self.enabled:
            return {"available": False, "error": "No API key"}
        
        # Only works for IPs
        if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', target):
            return {"available": False, "error": "Not an IP"}
        
        cache_key = f"abuseipdb_{target}"
        cached = _get_cache(cache_key)
        if cached:
            return cached
        
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": self.api_key, "Accept": "application/json"}
        params = {"ipAddress": target, "maxAgeInDays": 90}
        
        try:
            async with session.get(url, headers=headers, params=params, timeout=10) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    score = data['data']['abuseConfidenceScore']
                    reports = len(data['data'].get('reports', []))
                    result = {
                        "available": True,
                        "abuse_score": score,
                        "total_reports": reports,
                        "is_malicious": score > 50,
                    }
                    _set_cache(cache_key, result)
                    return result
                else:
                    error_text = await resp.text()
                    logger.warning(f"AbuseIPDB error {resp.status}: {error_text[:200]}")
                    return {"available": False, "error": f"HTTP {resp.status}"}
        except Exception as e:
            logger.exception(f"AbuseIPDB lookup failed for {target}: {e}")
            return {"available": False, "error": str(e)}

# --- URLhaus Provider ---
class URLhausProvider(ThreatIntelProvider):
    def __init__(self):
        self.enabled = True
    
    async def lookup(self, session: aiohttp.ClientSession, target: str) -> Dict[str, Any]:
        # Only works for URLs
        if not target.startswith(('http://', 'https://')):
            return {"available": False, "error": "Not a URL"}
        
        cache_key = f"urlhaus_{target}"
        cached = _get_cache(cache_key)
        if cached:
            return cached
        
        url = "https://urlhaus-api.abuse.ch/v1/url/"
        data = {"url": target}
        
        try:
            async with session.post(url, data=data, timeout=10) as resp:
                if resp.status == 200:
                    result_data = await resp.json()
                    if result_data.get("query_status") == "ok":
                        result = {
                            "available": True,
                            "is_malicious": True,
                            "threat": result_data.get('threat', 'Unknown'),
                            "reporter": result_data.get('reporter', 'Unknown'),
                            "date_added": result_data.get('date_added', 'Unknown'),
                            "reference": result_data.get('urlhaus_reference', ''),
                        }
                        _set_cache(cache_key, result)
                        return result
                    else:
                        # Not found or invalid
                        result = {"available": True, "not_found": True}
                        _set_cache(cache_key, result)
                        return result
                else:
                    error_text = await resp.text()
                    logger.warning(f"URLhaus error {resp.status}: {error_text[:200]}")
                    return {"available": False, "error": f"HTTP {resp.status}"}
        except Exception as e:
            logger.exception(f"URLhaus lookup failed for {target}: {e}")
            return {"available": False, "error": str(e)}

# --- IOC Extraction ---
def extract_iocs(text: str) -> Dict[str, Set[str]]:
    """Extract domains, IPs, URLs, emails, hashes from text."""
    iocs = {"domains": set(), "ips": set(), "urls": set(), "emails": set(), "hashes": set()}
    
    # URLs
    url_pattern = r'https?://[^\s<>"\'\)]+'
    urls = set(re.findall(url_pattern, text))
    iocs["urls"] = urls
    
    # IPs
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    ips = set(re.findall(ip_pattern, text))
    iocs["ips"] = ips
    
    # Domains (from URLs)
    for url in urls:
        domain_match = re.search(r'https?://([^/]+)', url)
        if domain_match:
            domain = domain_match.group(1)
            # remove port if present
            domain = domain.split(':')[0]
            iocs["domains"].add(domain)
    
    # Emails
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    emails = set(re.findall(email_pattern, text))
    iocs["emails"] = emails
    
    # Hashes (MD5, SHA1, SHA256)
    md5_pattern = r'\b[a-fA-F0-9]{32}\b'
    sha1_pattern = r'\b[a-fA-F0-9]{40}\b'
    sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
    hashes = set(re.findall(md5_pattern, text)) | set(re.findall(sha1_pattern, text)) | set(re.findall(sha256_pattern, text))
    iocs["hashes"] = hashes
    
    return iocs

# --- Confidence Calculation ---
def calculate_confidence(result: Dict[str, Any], provider: str) -> int:
    """Calculate confidence score (0-100) based on provider result."""
    if provider == "VirusTotal":
        if result.get("is_malicious"):
            # Score based on ratio of malicious/total
            malicious = result.get("malicious", 0)
            total = result.get("total", 1)
            return min(100, int((malicious / total) * 100 + 20))
        else:
            return 0
    elif provider == "AbuseIPDB":
        score = result.get("abuse_score", 0)
        return score  # Already 0-100
    elif provider == "URLhaus":
        if result.get("is_malicious"):
            return 100
        else:
            return 0
    return 0

# --- Main Enrichment Functions ---
def providers_list() -> List[ThreatIntelProvider]:
    """Return list of enabled providers based on environment variables."""
    providers = []
    if VIRUSTOTAL_API_KEY:
        providers.append(VirusTotalProvider())
    if ABUSEIPDB_API_KEY:
        providers.append(AbuseIPDBProvider())
    providers.append(URLhausProvider())  # Always enabled
    return providers

async def enrich_iocs_async(iocs: Dict[str, Set[str]], enabled_providers: List[ThreatIntelProvider] = None) -> List[Finding]:
    """Run threat intelligence enrichment on all IOCs using async gather."""
    if enabled_providers is None:
        enabled_providers = providers_list()
    
    findings = []
    # Collect all targets: domains, IPs, URLs
    targets = []
    targets.extend([("domain", d) for d in iocs["domains"]])
    targets.extend([("ip", ip) for ip in iocs["ips"]])
    targets.extend([("url", url) for url in iocs["urls"]])
    # Also emails, hashes - but only if providers support them (not yet)
    
    # Skip private IPs and localhost
    targets = [t for t in targets if not re.match(r'^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|127\.|localhost)', t[1])]
    
    if not targets:
        return findings
    
    # For each provider, perform lookups in parallel
    async with aiohttp.ClientSession() as session:
        tasks = []
        # For each target and provider, create a task
        for target_type, target_value in targets:
            for provider in enabled_providers:
                # Some providers only support specific types
                if isinstance(provider, AbuseIPDBProvider) and target_type != "ip":
                    continue
                if isinstance(provider, URLhausProvider) and target_type != "url":
                    continue
                # VirusTotal supports domains and IPs
                if isinstance(provider, VirusTotalProvider) and target_type not in ["domain", "ip"]:
                    continue
                tasks.append((target_value, provider, provider.lookup(session, target_value)))
        
        # Run all lookups concurrently
        results = await asyncio.gather(*[task[2] for task in tasks], return_exceptions=True)
        
        # Process results
        for idx, (target_value, provider, result) in enumerate(zip([t[0] for t in tasks], [t[1] for t in tasks], results)):
            if isinstance(result, Exception):
                logger.error(f"Provider {provider.name()} lookup failed for {target_value}: {result}")
                continue
            if not result.get("available"):
                continue
            if result.get("not_found"):
                continue
            
            # Determine if malicious
            is_malicious = False
            evidence = {}
            confidence = 0
            if isinstance(provider, VirusTotalProvider):
                is_malicious = result.get("is_malicious", False)
                evidence = {
                    "malicious": result.get("malicious", 0),
                    "suspicious": result.get("suspicious", 0),
                    "total": result.get("total", 1),
                }
                confidence = calculate_confidence(result, "VirusTotal")
            elif isinstance(provider, AbuseIPDBProvider):
                is_malicious = result.get("is_malicious", False)
                evidence = {
                    "abuse_score": result.get("abuse_score", 0),
                    "reports": result.get("total_reports", 0),
                }
                confidence = result.get("abuse_score", 0)
            elif isinstance(provider, URLhausProvider):
                is_malicious = result.get("is_malicious", False)
                evidence = {
                    "threat": result.get("threat", "Unknown"),
                    "reporter": result.get("reporter", "Unknown"),
                    "date_added": result.get("date_added", "Unknown"),
                }
                confidence = 100 if is_malicious else 0
            
            if is_malicious:
                findings.append(Finding(
                    module=f"Threat Intelligence ({provider.name()})",
                    category=f"Malicious {target_type.capitalize()} ({provider.name()})",
                    severity=Severity.CRITICAL,
                    description=f"{target_value} is flagged as malicious by {provider.name()}",
                    evidence=evidence,
                    confidence=confidence,
                    mitre_technique="T1566.002"
                ))
            elif confidence > 50 and not is_malicious:
                # Suspicious but not confirmed malicious
                findings.append(Finding(
                    module=f"Threat Intelligence ({provider.name()})",
                    category=f"Suspicious {target_type.capitalize()} ({provider.name()})",
                    severity=Severity.HIGH,
                    description=f"{target_value} is suspicious according to {provider.name()}",
                    evidence=evidence,
                    confidence=confidence,
                    mitre_technique="T1566.002"
                ))
    
    return findings

async def run_threat_intel(context) -> List[Finding]:
    """Asynchronously run threat intelligence enrichment on all IOCs."""
    # Extract IOCs from email content
    iocs = extract_iocs(context.email_content)
    # Also add existing domains/urls from context
    for domain in context.domains:
        iocs["domains"].add(domain)
    for url in context.urls:
        iocs["urls"].add(url)
    
    # Directly await the async function (no new loop)
    findings = await enrich_iocs_async(iocs)
    return findings
