import re
import whois
import dns.resolver
from datetime import datetime
from typing import Dict, Any, List
from .models import Finding, Severity

def enrich_domain(domain: str, vt_api_key: str = None) -> Dict[str, Any]:
    """Enrich a domain with WHOIS, DNS, and optional VirusTotal data."""
    info = {
        'domain': domain,
        'age_days': None,
        'registrar': 'Unknown',
        'country': 'Unknown',
        'has_mx': False,
        'has_spf': False,
        'has_dmarc': False,
        'is_new': False,
        'malicious': 0,
        'suspicious': 0,
        'is_malicious': False,
    }
    
    # 1. WHOIS
    try:
        w = whois.whois(domain)
        if w.creation_date:
            creation = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
            age = (datetime.now() - creation).days
            info['age_days'] = age
            info['is_new'] = age < 30
            info['registrar'] = w.registrar or 'Unknown'
            info['country'] = w.country or 'Unknown'
    except:
        pass
    
    # 2. DNS
    try:
        dns.resolver.resolve(domain, 'MX')
        info['has_mx'] = True
    except:
        pass
    try:
        txt = dns.resolver.resolve(domain, 'TXT')
        for record in txt:
            if 'v=spf1' in str(record):
                info['has_spf'] = True
                break
    except:
        pass
    try:
        dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
        info['has_dmarc'] = True
    except:
        pass
    
    # 3. VirusTotal (if API key provided)
    if vt_api_key:
        import requests
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": vt_api_key}
        try:
            resp = requests.get(url, headers=headers, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                stats = data['data']['attributes']['last_analysis_stats']
                info['malicious'] = stats.get('malicious', 0)
                info['suspicious'] = stats.get('suspicious', 0)
                info['is_malicious'] = stats.get('malicious', 0) > 0
        except:
            pass
    
    return info

def generate_domain_findings(domain_info: Dict[str, Any]) -> List[Finding]:
    """Convert domain info into findings."""
    findings = []
    
    if domain_info.get('is_new'):
        findings.append(Finding(
            module="Domain Intelligence",
            category="Newly Registered Domain",
            severity=Severity.HIGH,
            description=f"Domain '{domain_info['domain']}' is less than 30 days old (age: {domain_info['age_days']} days).",
            evidence=f"Registrar: {domain_info.get('registrar', 'Unknown')}",
            mitre_technique="T1566.002"
        ))
    
    if not domain_info.get('has_mx'):
        findings.append(Finding(
            module="Domain Intelligence",
            category="Missing MX Records",
            severity=Severity.MEDIUM,
            description=f"Domain '{domain_info['domain']}' has no mail exchange (MX) records.",
            mitre_technique="T1566.002"
        ))
    
    if domain_info.get('is_malicious'):
        findings.append(Finding(
            module="Domain Intelligence",
            category="Malicious Domain (VirusTotal)",
            severity=Severity.CRITICAL,
            description=f"Domain '{domain_info['domain']}' is flagged as malicious by VirusTotal ({domain_info['malicious']} engines).",
            mitre_technique="T1566.002"
        ))
    
    return findings