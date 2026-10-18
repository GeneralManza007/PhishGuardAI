# app/engine/brand.py
import re
from typing import List, Set, Tuple
from .models import Finding, Severity, AnalysisContext

# Known brands with their official domains
BRANDS = {
    'microsoft': ['microsoft.com', 'live.com', 'outlook.com', 'office.com'],
    'paypal': ['paypal.com', 'paypal-mail.com'],
    'apple': ['apple.com', 'icloud.com'],
    'google': ['google.com', 'gmail.com', 'youtube.com', 'drive.google.com'],
    'amazon': ['amazon.com', 'aws.amazon.com'],
    'facebook': ['facebook.com', 'fb.com', 'messenger.com'],
    'linkedin': ['linkedin.com'],
    'dropbox': ['dropbox.com'],
    'adobe': ['adobe.com'],
    'netflix': ['netflix.com'],
    'bank_of_america': ['bankofamerica.com'],
    'chase': ['chase.com'],
    'hmrc': ['hmrc.gov.uk'],
    'gov_uk': ['gov.uk'],
}

# Brand display names
BRAND_DISPLAY = {
    'microsoft': 'Microsoft',
    'paypal': 'PayPal',
    'apple': 'Apple',
    'google': 'Google',
    'amazon': 'Amazon',
    'facebook': 'Facebook',
    'linkedin': 'LinkedIn',
    'dropbox': 'Dropbox',
    'adobe': 'Adobe',
    'netflix': 'Netflix',
    'bank_of_america': 'Bank of America',
    'chase': 'Chase',
    'hmrc': 'HMRC',
    'gov_uk': 'UK Government',
}

def detect_brands(text: str) -> List[str]:
    """Detect if text contains any brand names."""
    detected = []
    text_lower = text.lower()
    
    for brand, domains in BRANDS.items():
        # Check for brand name in text
        display_name = BRAND_DISPLAY.get(brand, brand)
        if display_name.lower() in text_lower:
            detected.append(brand)
        # Check for domains
        for domain in domains:
            if domain in text_lower:
                detected.append(brand)
                break
    
    return list(set(detected))

def check_domain_impersonation(domain: str, brands: List[str]) -> List[Tuple[str, str]]:
    """
    Check if a domain impersonates a known brand.
    Returns list of (brand, confidence) tuples.
    """
    impersonations = []
    domain_lower = domain.lower()
    
    for brand, domains in BRANDS.items():
        for legit_domain in domains:
            # Check if domain contains the legit domain as a substring
            if legit_domain in domain_lower and domain_lower != legit_domain:
                # This is a typosquat or subdomain impersonation
                impersonations.append((brand, "High"))
                break
            
            # Check for common typosquatting patterns
            # e.g., paypa1.com vs paypal.com
            common_substitutions = [
                ('0', 'o'), ('1', 'i'), ('3', 'e'), ('4', 'a'),
                ('5', 's'), ('rn', 'm'), ('vv', 'w'), ('cl', 'd')
            ]
            
            test_domain = domain_lower
            for old, new in common_substitutions:
                test_domain = test_domain.replace(old, new)
            
            if legit_domain in test_domain and domain_lower != legit_domain:
                impersonations.append((brand, "High"))
                break
    
    return impersonations

def analyze_brands(email_content: str, urls: List[str], context: AnalysisContext) -> List[Finding]:
    """Main entry point for brand detection."""
    findings = []
    brands = detect_brands(email_content)
    context.brands_detected = brands
    
    if not brands:
        return findings
    
    # Check each URL for brand impersonation
    for url in urls:
        # Extract domain from URL
        domain_match = re.search(r'https?://([^/]+)', url)
        if domain_match:
            domain = domain_match.group(1)
            impersonations = check_domain_impersonation(domain, brands)
            
            for brand, confidence in impersonations:
                display_name = BRAND_DISPLAY.get(brand, brand)
                findings.append(Finding(
                    module="Brand Detection",
                    category="Brand Impersonation",
                    severity=Severity.CRITICAL,
                    description=f"Domain '{domain}' impersonates {display_name}.",
                    evidence=f"Brand: {display_name} | Domain: {domain}",
                    mitre_technique="T1566.002"
                ))
    
    # If we detected brands but no impersonation yet, add an info finding
    if findings:
        display_names = [BRAND_DISPLAY.get(b, b) for b in brands]
        findings.append(Finding(
            module="Brand Detection",
            category="Brand Mention Detected",
            severity=Severity.INFO,
            description=f"Email mentions or references: {', '.join(display_names)}.",
            mitre_technique="T1566.002"
        ))
    
    return findings