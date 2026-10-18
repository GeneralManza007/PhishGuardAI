# app/engine/ioc.py
import re
from typing import List, Dict, Set, Any
from .models import Finding, Severity, AnalysisContext

def extract_ips(text: str) -> Set[str]:
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    ips = set()
    for ip in re.findall(ip_pattern, text):
        parts = ip.split('.')
        if all(0 <= int(p) <= 255 for p in parts):
            ips.add(ip)
    return ips

def extract_emails(text: str) -> Set[str]:
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    return set(re.findall(email_pattern, text))

def extract_phone_numbers(text: str) -> Set[str]:
    patterns = [
        r'\+\d{1,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}',
        r'\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}',
        r'\d{5}[-.\s]?\d{6}',
    ]
    phones = set()
    for pattern in patterns:
        phones.update(re.findall(pattern, text))
    return phones

def extract_bitcoin_addresses(text: str) -> Set[str]:
    btc_pattern = r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'
    return set(re.findall(btc_pattern, text))

def extract_hashes(text: str) -> Dict[str, Set[str]]:
    hashes = {'md5': set(), 'sha1': set(), 'sha256': set()}
    md5_pattern = r'\b[a-fA-F0-9]{32}\b'
    sha1_pattern = r'\b[a-fA-F0-9]{40}\b'
    sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
    hashes['md5'] = set(re.findall(md5_pattern, text, re.IGNORECASE))
    hashes['sha1'] = set(re.findall(sha1_pattern, text, re.IGNORECASE))
    hashes['sha256'] = set(re.findall(sha256_pattern, text, re.IGNORECASE))
    return {k: v for k, v in hashes.items() if v}

def extract_domains(text: str) -> Set[str]:
    domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    domains = set(re.findall(domain_pattern, text))
    # Filter out common false positives
    domains = {d for d in domains if '.' in d and len(d) > 3}
    return domains

def extract_attachments(text: str) -> Set[str]:
    pattern = r'filename\s*=\s*["\']?([^"\'\s]+)["\']?'
    matches = set(re.findall(pattern, text, re.IGNORECASE))
    pattern2 = r'Content-Disposition:.*filename\s*=\s*["\']?([^"\'\s]+)["\']?'
    matches2 = set(re.findall(pattern2, text, re.IGNORECASE))
    return matches.union(matches2)

def extract_all_iocs(text: str) -> Dict[str, List[str]]:
    """Extract all IOCs from text and return as dict of lists."""
    return {
        "iPs": list(extract_ips(text)),
        "emails": list(extract_emails(text)),
        "phones": list(extract_phone_numbers(text)),
        "bitcoin": list(extract_bitcoin_addresses(text)),
        "hashes": {k: list(v) for k, v in extract_hashes(text).items()},
        "domains": list(extract_domains(text)),
        "attachments": list(extract_attachments(text)),
    }

def extract_iocs(email_content: str, context: AnalysisContext) -> List[Finding]:
    """Main entry point: extract IOCs, store in context, return findings."""
    iocs = extract_all_iocs(email_content)
    # Add URLs from context (already extracted elsewhere)
    iocs["urls"] = context.urls
    context.iocs = iocs  # store for use in response
    
    findings = []
    for ioc_type, values in iocs.items():
        if not values or ioc_type == "hashes":
            continue
        if ioc_type in ["urls", "domains"]:
            # Skip these to avoid duplication with URL analysis findings
            continue
        findings.append(Finding(
            module="IOC Extraction",
            category=f"{ioc_type.capitalize()} Indicator",
            severity=Severity.HIGH,
            description=f"Found {len(values)} {ioc_type}(s) in email.",
            evidence={ioc_type: values[:5]},
            mitre_technique="T1566.002"
        ))
    
    # Hash findings
    hashes = iocs.get("hashes", {})
    if hashes:
        hash_types = [f"{k.upper()} ({len(v)})" for k, v in hashes.items()]
        findings.append(Finding(
            module="IOC Extraction",
            category="Hash Indicator",
            severity=Severity.HIGH,
            description=f"Found hashes: {', '.join(hash_types)}.",
            evidence=hashes,
            mitre_technique="T1566.002"
        ))
    
    return findings