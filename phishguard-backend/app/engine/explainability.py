# app/engine/explainability.py
import re
from typing import List, Dict, Any

# Keywords that trigger specific findings
KEYWORD_MAP = {
    "Credential Harvesting": [
        "password", "verify", "confirm", "credential", "login", "sign in",
        "account", "identity", "reset", "update your", "click here"
    ],
    "Urgency Manipulation": [
        "urgent", "immediate", "as soon as possible", "within 24 hours",
        "limited time", "expire", "suspension", "locked", "suspended",
        "unusual activity", "security alert"
    ],
    "Financial Scam": [
        "bank", "credit card", "paypal", "payment", "invoice", "refund",
        "transaction", "withdraw", "deposit"
    ],
    "Data Harvesting": [
        "ssn", "social security", "date of birth", "address", "phone number",
        "email", "confirm your information"
    ],
    "Brand Impersonation": [
        "microsoft", "google", "apple", "amazon", "paypal", "facebook",
        "linkedin", "dropbox", "adobe", "bank of america", "chase", "wells fargo"
    ],
    "Suspicious URL": [
        "http://", ".top", ".ru", ".tk", ".xyz", ".click", ".download"
    ],
    "Insecure Connection": [
        "http://"
    ]
}

# Map severity to color classes
COLOR_MAP = {
    "Critical": "bg-red-100 text-red-800 border-red-400",
    "High": "bg-orange-100 text-orange-800 border-orange-400",
    "Medium": "bg-yellow-100 text-yellow-800 border-yellow-400",
    "Low": "bg-blue-100 text-blue-800 border-blue-400"
}

def extract_snippets(text: str, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Extract the exact text snippets from the email that triggered each finding.
    Returns a list of highlights with positions.
    """
    highlights = []
    seen_urls = set()  # Track URLs we've already processed
    
    for finding in findings:
        category = finding.get("category", "")
        severity = finding.get("severity", "Low")
        description = finding.get("description", "")
        
        # Special handling for URL findings - deduplicate
        if category == "Suspicious URL" or category == "Insecure Connection":
            # Extract URLs from the text
            url_pattern = r'https?://[^\s<>"\'\)]+'
            for url in re.findall(url_pattern, text, re.IGNORECASE):
                url_lower = url.lower()
                if url_lower in seen_urls:
                    continue  # Skip duplicate URLs
                seen_urls.add(url_lower)
                
                start = text.lower().find(url_lower)
                if start != -1:
                    # For URL findings, always use Critical severity
                    actual_severity = "Critical" if category == "Suspicious URL" else "Medium"
                    highlights.append({
                        "text": url,
                        "startIndex": start,
                        "endIndex": start + len(url),
                        "severity": actual_severity,
                        "category": category,
                        "description": description
                    })
            continue
        
        # Get keywords for this category
        keywords = KEYWORD_MAP.get(category, [])
        
        # For all other findings, find keywords in the text
        for keyword in keywords:
            pattern = re.compile(re.escape(keyword), re.IGNORECASE)
            for match in pattern.finditer(text):
                start = match.start()
                end = match.end()
                
                # Get context (50 chars around)
                context_start = max(0, start - 15)
                context_end = min(len(text), end + 35)
                full_text = text[context_start:context_end]
                
                highlights.append({
                    "text": full_text,
                    "startIndex": context_start,
                    "endIndex": context_end,
                    "severity": severity,
                    "category": category,
                    "description": description
                })
    
    # Remove duplicates (same text and position)
    seen = set()
    unique_highlights = []
    for h in highlights:
        key = f"{h['startIndex']}-{h['endIndex']}"
        if key not in seen:
            seen.add(key)
            unique_highlights.append(h)
    
    return unique_highlights