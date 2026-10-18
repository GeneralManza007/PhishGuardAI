import re
from typing import Dict, List, Optional
from .models import Finding, Severity, AnalysisContext

def parse_headers(email_content: str) -> Dict[str, str]:
    """Extract headers from email content."""
    headers = {}
    lines = email_content.split('\n')
    
    for line in lines:
        if ': ' in line:
            key, value = line.split(': ', 1)
            headers[key.lower()] = value.strip()
        elif line.startswith(' ') or line.startswith('\t'):
            # Continuation line - append to previous header
            if headers:
                last_key = list(headers.keys())[-1]
                headers[last_key] += ' ' + line.strip()
        else:
            # Headers end when we hit a non-header line
            if headers:
                break
    
    return headers

def check_spf(headers: Dict[str, str]) -> Optional[str]:
    """Check SPF record (simplified - in production you'd do DNS lookups)."""
    received_spf = headers.get('received-spf', '')
    if 'pass' in received_spf.lower():
        return 'pass'
    elif 'fail' in received_spf.lower():
        return 'fail'
    return None

def check_dkim(headers: Dict[str, str]) -> Optional[str]:
    """Check DKIM signature."""
    dkim = headers.get('dkim-signature', '')
    if dkim:
        if 'v=1' in dkim:
            return 'present'
    return None

def check_dmarc(headers: Dict[str, str]) -> Optional[str]:
    """Check DMARC policy."""
    dmarc = headers.get('authentication-results', '')
    if 'dmarc=pass' in dmarc.lower():
        return 'pass'
    elif 'dmarc=fail' in dmarc.lower():
        return 'fail'
    return None

def check_reply_to(headers: Dict[str, str]) -> Optional[Dict[str, str]]:
    """Check if Reply-To differs from From."""
    from_addr = headers.get('from', '')
    reply_to = headers.get('reply-to', '')
    
    if reply_to and from_addr and reply_to != from_addr:
        # Extract domains
        from_domain = re.search(r'@([\w.-]+)', from_addr)
        reply_domain = re.search(r'@([\w.-]+)', reply_to)
        
        if from_domain and reply_domain:
            return {
                'from': from_domain.group(1),
                'reply_to': reply_domain.group(1),
                'mismatch': from_domain.group(1) != reply_domain.group(1)
            }
    return None

def analyze_headers(email_content: str) -> tuple[List[Finding], AnalysisContext]:
    """Main entry point for header analysis."""
    findings = []
    headers = parse_headers(email_content)
    context = AnalysisContext(email_content=email_content, headers=headers)
    
    # 1. SPF Check
    spf = check_spf(headers)
    if spf == 'fail':
        findings.append(Finding(
            module="Header Analysis",
            category="SPF Authentication",
            severity=Severity.HIGH,
            description="SPF check failed - sending server is not authorized to send mail on behalf of this domain.",
            mitre_technique="T1566.002"
        ))
        context.spf_result = 'fail'
    elif spf == 'pass':
        context.spf_result = 'pass'
    
    # 2. DKIM Check
    dkim = check_dkim(headers)
    if dkim != 'present':
        findings.append(Finding(
            module="Header Analysis",
            category="DKIM Signature",
            severity=Severity.MEDIUM,
            description="Email lacks DKIM signature - cannot verify sender authenticity.",
            mitre_technique="T1566.002"
        ))
        context.dkim_result = 'missing'
    
    # 3. DMARC Check
    dmarc = check_dmarc(headers)
    if dmarc == 'fail':
        findings.append(Finding(
            module="Header Analysis",
            category="DMARC Policy",
            severity=Severity.CRITICAL,
            description="DMARC check failed - domain policy rejected this email.",
            mitre_technique="T1566.002"
        ))
        context.dmarc_result = 'fail'
    
    # 4. Reply-To Mismatch (Classic phishing technique)
    reply_to_check = check_reply_to(headers)
    if reply_to_check and reply_to_check['mismatch']:
        findings.append(Finding(
            module="Header Analysis",
            category="Reply-To Mismatch",
            severity=Severity.HIGH,
            description=f"Reply-To domain ({reply_to_check['reply_to']}) differs from From domain ({reply_to_check['from']}).",
            evidence={
        "from": reply_to_check['from'],
        "reply_to": reply_to_check['reply_to']
    },
            mitre_technique="T1566.002"
        ))
    
    # 5. Check for "Return-Path" mismatch
    return_path = headers.get('return-path', '')
    from_addr = headers.get('from', '')
    if return_path and from_addr:
        return_domain = re.search(r'@([\w.-]+)', return_path)
        from_domain = re.search(r'@([\w.-]+)', from_addr)
        if return_domain and from_domain and return_domain.group(1) != from_domain.group(1):
            findings.append(Finding(
                module="Header Analysis",
                category="Return-Path Mismatch",
                severity=Severity.MEDIUM,
                description=f"Return-Path domain ({return_domain.group(1)}) differs from From domain ({from_domain.group(1)}).",
                mitre_technique="T1566.002"
            ))
    
    return findings, context