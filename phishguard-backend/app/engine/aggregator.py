# app/engine/aggregator.py
from typing import List
from .models import Finding, Severity, AnalysisResult, AnalysisContext

# Severity weights
SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 30,
    Severity.HIGH: 20,
    Severity.MEDIUM: 10,
    Severity.LOW: 5,
    Severity.INFO: 0,
}

MAX_RISK_SCORE = 100

def aggregate_risk(findings: List[Finding]) -> tuple[int, Severity]:
    """Calculate overall risk score and level."""
    total_score = 0
    
    for finding in findings:
        total_score += SEVERITY_WEIGHTS.get(finding.severity, 0)
    
    # Cap at 100
    total_score = min(total_score, MAX_RISK_SCORE)
    
    # Determine risk level
    if total_score >= 70:
        risk_level = Severity.CRITICAL
    elif total_score >= 50:
        risk_level = Severity.HIGH
    elif total_score >= 25:
        risk_level = Severity.MEDIUM
    elif total_score >= 10:
        risk_level = Severity.LOW
    else:
        risk_level = Severity.INFO
    
    return total_score, risk_level

def generate_summary(findings: List[Finding]) -> str:
    """Generate a human-readable summary."""
    if not findings:
        return "No threats detected."
    
    # Count by severity
    severity_counts = {s: 0 for s in Severity}
    for f in findings:
        severity_counts[f.severity] += 1
    
    summary_parts = []
    for severity in Severity:
        if severity_counts[severity] > 0:
            summary_parts.append(f"{severity_counts[severity]} {severity.value}")
    
    return f"Found {len(findings)} issues: " + ", ".join(summary_parts)