# app/engine/content.py
import re
from typing import List, Dict, Any
from transformers import pipeline

# --- Global model (loads once when the server starts) ---
_classifier = None

def get_classifier():
    """Lazy-load the zero-shot classifier."""
    global _classifier
    if _classifier is None:
        # Using BART-large-MNLI - great for zero-shot with good explainability
        _classifier = pipeline("zero-shot-classification", 
                               model="facebook/bart-large-mnli",
                               device=-1)  # -1 = CPU, 0 = GPU if available
    return _classifier

# --- Configuration ---
# These are the "labels" we want the AI to detect
PHISHING_LABELS = [
    "credential request", 
    "urgency", 
    "impersonation",
    "account suspension",
    "financial request",
    "personal information request"
]

# Map labels to severity and human-readable categories
LABEL_MAPPING = {
    "credential request": {"category": "Credential Harvesting", "severity": "Critical"},
    "urgency": {"category": "Urgency Manipulation", "severity": "High"},
    "impersonation": {"category": "Brand Impersonation", "severity": "Critical"},
    "account suspension": {"category": "Threat/Scare Tactic", "severity": "High"},
    "financial request": {"category": "Financial Scam", "severity": "Critical"},
    "personal information request": {"category": "Data Harvesting", "severity": "High"},
}

def analyze_content(email_text: str) -> List[Dict[str, Any]]:
    """
    Use zero-shot AI to classify the email content against phishing indicators.
    Returns list of findings.
    """
    if not email_text or len(email_text) < 20:
        return []  # Too short to analyze meaningfully
    
    findings = []
    classifier = get_classifier()
    
    # Run the AI classification
    # We limit to top 3 labels to avoid noise
    result = classifier(email_text, PHISHING_LABELS, multi_label=True)
    
    # result = {'labels': ['urgency', 'credential request', ...], 
    #           'scores': [0.98, 0.92, ...]}
    
    for label, score in zip(result['labels'], result['scores']):
        # Only flag if the confidence is high (> 0.7)
        if score > 0.7:
            mapped = LABEL_MAPPING.get(label, None)
            if mapped:
                findings.append({
                    "category": mapped["category"],
                    "severity": mapped["severity"],
                    "description": f"AI detected: '{label}' with {int(score * 100)}% confidence"
                })
    
    return findings