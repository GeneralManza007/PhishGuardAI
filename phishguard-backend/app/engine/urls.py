# app/engine/urls.py
import re
import urllib.parse
from typing import List, Dict, Any
import tldextract

# --- Configuration ---
SUSPICIOUS_TLDS = {'.tk', '.top', '.ru', '.cc', '.cn', '.ml', '.ga', '.cf', '.click', '.download', '.stream'}
SHORTENERS = {'bit.ly', 'tinyurl.com', 'short.url', 'goo.gl', 'ow.ly', 'buff.ly', 't.co', 'tiny.cc', 'is.gd'}
BRANDS = ['microsoft', 'google', 'paypal', 'apple', 'amazon', 'facebook', 'linkedin', 'dropbox', 'adobe', 'bank']

# --- Core Functions ---

def extract_urls(text: str) -> List[str]:
    """Extract all URLs from the email text using regex."""
    # Simple but effective regex for URLs
    pattern = r'https?://[^\s<>"\'\)]+|[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:/\S*)?'
    raw_urls = re.findall(pattern, text)
    
    # Clean up trailing punctuation
    cleaned = []
    for url in raw_urls:
        url = url.rstrip('.,;:!?')
        if url.startswith(('http://', 'https://')):
            cleaned.append(url)
        else:
            # If no scheme, assume http (but we'll flag it later)
            cleaned.append(f'http://{url}')
    return list(set(cleaned))  # Remove duplicates

def is_ip_address(domain: str) -> bool:
    """Check if domain is an IP address (like 192.168.1.1)."""
    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    if re.match(ip_pattern, domain):
        return all(0 <= int(part) <= 255 for part in domain.split('.'))
    return False

def is_shortened_url(domain: str) -> bool:
    """Check if domain is a known URL shortener."""
    return domain.lower() in SHORTENERS

def detect_typosquatting(domain: str) -> List[str]:
    """
    Check for typosquatting by looking for common substitutions.
    Returns list of brands being impersonated.
    """
    lower_domain = domain.lower()
    # Remove www. and subdomains for matching
    parts = lower_domain.split('.')
    main_part = parts[-2] if len(parts) > 1 else parts[0]
    
    # Common substitution maps
    substitutions = {
        '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's',
        'rn': 'm', 'vv': 'w', 'cl': 'd', 'vvw': 'ww'
    }
    
    # Check against known brands
    for brand in BRANDS:
        # Direct match
        if brand in main_part:
            # But if it's exactly the brand, it's not typosquatting
            if main_part == brand:
                continue
            return [brand]
        
        # Check substitutions
        test_str = main_part
        for old, new in substitutions.items():
            test_str = test_str.replace(old, new)
        
        if brand in test_str or test_str in brand:
            return [brand]
    
    return []

def check_suspicious_tld(domain: str) -> bool:
    """Check if TLD is suspicious."""
    ext = tldextract.extract(domain)
    suffix = ext.suffix
    if suffix:
        return f'.{suffix}' in SUSPICIOUS_TLDS
    return False

def analyze_urls(email_text: str) -> List[Dict[str, Any]]:
    """
    Main entry point for URL analysis.
    Returns a list of findings (each with category, severity, description).
    """
    findings = []
    urls = extract_urls(email_text)
    
    if not urls:
        return findings
    
    for url in urls:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc or parsed.path
        scheme = parsed.scheme
        
        # Check 1: IP Address
        if is_ip_address(domain):
            findings.append({
                "category": "Suspicious URL",
                "severity": "Critical",
                "description": f"URL uses raw IP address instead of domain name: {url}"
            })
            continue  # Skip other checks for this URL to avoid noise
        
        # Check 2: Shortened URL
        if is_shortened_url(domain):
            findings.append({
                "category": "Suspicious URL",
                "severity": "High",
                "description": f"URL uses a known link shortener (obscures destination): {domain}"
            })
        
        # Check 3: Typosquatting
        impersonated = detect_typosquatting(domain)
        if impersonated:
            findings.append({
                "category": "Typosquatting / Brand Impersonation",
                "severity": "Critical",
                "description": f"Domain '{domain}' impersonates '{', '.join(impersonated)}'"
            })
        
        # Check 4: Suspicious TLD
        if check_suspicious_tld(domain):
            findings.append({
                "category": "Suspicious TLD",
                "severity": "High",
                "description": f"Domain uses a TLD commonly associated with spam/malware: {domain}"
            })
        
        # Check 5: Missing HTTPS
        if scheme != 'https':
            findings.append({
                "category": "Insecure Connection",
                "severity": "Medium",
                "description": f"URL does not use HTTPS: {url}"
            })
    
    return findings