# app/engine/postprocess.py
from typing import List, Dict, Any
from .models import Finding, Severity
import re

def group_findings(findings: List[Finding], email_content: str, urls: List[str]) -> List[Finding]:
    """
    Post-process findings to group repetitive ones.
    - Consolidate "Insecure Connection" findings
    - Consolidate "Missing MX Records" findings
    - Add a "URL Summary" finding
    """
    # Separate out findings to keep vs group
    kept = []
    insecure_urls = []
    missing_mx_domains = []
    url_summary = {"total": 0, "http": 0, "typosquatting": 0, "mx_missing": 0}

    for f in findings:
        # Check for Insecure Connection
        if f.category == "Insecure Connection":
            # Extract URL from description
            match = re.search(r'URL does not use HTTPS: (http://[^\s]+)', f.description)
            if match:
                insecure_urls.append(match.group(1))
            # Don't add to kept yet
            continue
        
        # Check for Missing MX Records
        if f.category == "Missing MX Records":
            # Extract domain from description
            match = re.search(r"Domain '([^']+)' has no mail exchange", f.description)
            if match:
                missing_mx_domains.append(match.group(1))
            # Don't add to kept yet
            continue
        
        # Keep all other findings
        kept.append(f)
    
    # If we have insecure URLs, create a grouped finding
    if insecure_urls:
        # Deduplicate
        insecure_urls = list(dict.fromkeys(insecure_urls))
        # Build description
        desc = f"Found {len(insecure_urls)} URLs using insecure HTTP:\n" + "\n".join(f"- {url}" for url in insecure_urls)
        kept.append(Finding(
            module="URL Analysis",
            category="Insecure Connections (Grouped)",
            severity=Severity.MEDIUM,
            description=desc,
            mitre_technique="T1566.002"
        ))
    
    # If we have missing MX domains, create a grouped finding
    if missing_mx_domains:
        missing_mx_domains = list(dict.fromkeys(missing_mx_domains))
        desc = f"Found {len(missing_mx_domains)} domains with missing MX records:\n" + "\n".join(f"- {domain}" for domain in missing_mx_domains)
        kept.append(Finding(
            module="Domain Intelligence",
            category="Missing MX Records (Grouped)",
            severity=Severity.MEDIUM,
            description=desc,
            mitre_technique="T1566.002"
        ))
    
    if urls:
            summary_lines = []
            summary_lines.append(f"Total URLs analyzed: {len(urls)}")
            if insecure_urls:
                summary_lines.append(f"  - {len(insecure_urls)} used HTTP (insecure)")
            # Count typosquatting from existing findings (we could track separately)
            # For now, just add a note if we have typosquatting findings
            typosquatting_findings = [f for f in findings if "Typosquatting" in f.category]
            if typosquatting_findings:
                summary_lines.append(f"  - {len(typosquatting_findings)} domains showed typosquatting")
            if missing_mx_domains:
                summary_lines.append(f"  - {len(missing_mx_domains)} domains missing MX records")
            kept.append(Finding(
                module="URL Analysis",
                category="URL Summary",
                severity=Severity.INFO,
                description="\n".join(summary_lines)
            ))

    merged_findings = []
    seen = set()
    for f in kept:
        key = f"{f.module}-{f.category}"
        if key in seen:
            # Merge descriptions (combine)
            for existing in merged_findings:
                if existing.module == f.module and existing.category == f.category:
                    existing.description = f"{existing.description} | {f.description}"
                    break
        else:
            seen.add(key)
            merged_findings.append(f)

    print(f"[POSTPROCESS] kept count: {len(kept)}, merged_findings count: {len(merged_findings)}")
    for f in merged_findings:
        print(f"  - {f.category}")

    return merged_findings
