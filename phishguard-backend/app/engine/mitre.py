# app/engine/mitre.py
"""
MITRE ATT&CK mapping - only for actual techniques.
"""

# Mapping for categories that are genuine ATT&CK techniques
TECHNIQUE_MAP = {
    "Credential Harvesting": {
        "technique_id": "T1566.002",
        "name": "Spearphishing Link",
        "tactic": "Credential Access",
        "description": "Adversaries steal credentials via phishing.",
        "url": "https://attack.mitre.org/techniques/T1566/002/"
    },
    "Credential Request": {
        "technique_id": "T1566.002",
        "name": "Spearphishing Link",
        "tactic": "Credential Access",
        "description": "Adversaries steal credentials via phishing.",
        "url": "https://attack.mitre.org/techniques/T1566/002/"
    },
    "Phishing": {
        "technique_id": "T1566",
        "name": "Phishing",
        "tactic": "Initial Access",
        "description": "Adversaries send phishing messages to gain access.",
        "url": "https://attack.mitre.org/techniques/T1566/"
    },
    "Spearphishing Link": {
        "technique_id": "T1566.002",
        "name": "Spearphishing Link",
        "tactic": "Initial Access",
        "description": "Adversaries send emails with malicious links.",
        "url": "https://attack.mitre.org/techniques/T1566/002/"
    },
    "Brand Impersonation": {
        "technique_id": "T1566.002",
        "name": "Spearphishing Link",
        "tactic": "Initial Access",
        "description": "Adversaries impersonate legitimate brands.",
        "url": "https://attack.mitre.org/techniques/T1566/002/"
    },
    "Typosquatting / Brand Impersonation": {
        "technique_id": "T1566.002",
        "name": "Spearphishing Link",
        "tactic": "Initial Access",
        "description": "Adversaries use typosquatting to impersonate brands.",
        "url": "https://attack.mitre.org/techniques/T1566/002/"
    },
    "Threat/Scare Tactic": {
        "technique_id": "T1566.002",
        "name": "Spearphishing Link",
        "tactic": "Initial Access",
        "description": "Adversaries use fear to pressure victims.",
        "url": "https://attack.mitre.org/techniques/T1566/002/"
    },
    "Urgency Manipulation": {
        "technique_id": "T1566.002",
        "name": "Spearphishing Link",
        "tactic": "Initial Access",
        "description": "Adversaries create urgency to rush victims.",
        "url": "https://attack.mitre.org/techniques/T1566/002/"
    },
    "Data Harvesting": {
        "technique_id": "T1566.002",
        "name": "Spearphishing Link",
        "tactic": "Credential Access",
        "description": "Adversaries harvest personal information.",
        "url": "https://attack.mitre.org/techniques/T1566/002/"
    },
    "Financial Scam": {
        "technique_id": "T1566.002",
        "name": "Spearphishing Link",
        "tactic": "Impact",
        "description": "Adversaries attempt financial fraud.",
        "url": "https://attack.mitre.org/techniques/T1566/002/"
    },
}
def map_to_mitre(category: str) -> dict:
    """
    Return MITRE ATT&CK info if category is a technique.
    Otherwise return type: 'evidence' with no technique fields.
    """
    if category in TECHNIQUE_MAP:
        info = TECHNIQUE_MAP[category]
        return {
            "type": "technique",
            "technique_id": info["technique_id"],
            "tactic": info["tactic"],
            "name": info["name"],
            "url": info["url"],
        }
    
    # Partial match (optional fallback)
    for key in TECHNIQUE_MAP:
        if key.lower() in category.lower() or category.lower() in key.lower():
            info = TECHNIQUE_MAP[key]
            return {
                "type": "technique",
                "technique_id": info["technique_id"],
                "tactic": info["tactic"],
                "name": info["name"],
                "url": info["url"],
            }
    
    # Not a technique
    return {
        "type": "evidence",
        "technique_id": None,
        "tactic": None,
        "name": None,
        "url": None,
    }