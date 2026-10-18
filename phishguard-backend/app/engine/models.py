from typing import List, Optional, Dict, Any
from pydantic import BaseModel
from enum import Enum

class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"

class Finding(BaseModel):
    module: str
    category: str
    severity: Severity
    description: str
    evidence: Optional[Dict[str, Any]] = None
    confidence: Optional[int] = None
    mitre_technique: Optional[str] = None
    mitre_tactic: Optional[str] = None
    mitre_url: Optional[str] = None
    type: str = "evidence"

class AnalysisContext(BaseModel):
    email_content: str
    headers: Dict[str, str] = {}
    urls: List[str] = []
    domains: List[str] = []
    attachments: List[Dict[str, Any]] = []
    
    # Enriched data
    spf_result: Optional[str] = None
    dkim_result: Optional[str] = None
    dmarc_result: Optional[str] = None
    brands_detected: List[str] = []
    iocs: List[Dict[str, Any]] = []

class AnalysisContext(BaseModel):
    email_content: str
    headers: Dict[str, str] = {}              
    urls: List[str] = []
    domains: List[str] = []
    attachments: List[Dict[str, Any]] = []
    spf_result: Optional[str] = None
    dkim_result: Optional[str] = None
    dmarc_result: Optional[str] = None
    brands_detected: List[str] = []
    iocs: List[Dict[str, Any]] = []

class AnalysisResult(BaseModel):
    findings: List[Finding]
    risk_score: int          
    risk_level: Severity
    context: AnalysisContext
    highlighted_snippets: List[Dict[str, Any]] = []