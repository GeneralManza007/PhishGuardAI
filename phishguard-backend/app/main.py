import re
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from datetime import datetime
import json
import os
from dotenv import load_dotenv
load_dotenv()

print(f"VT_KEY: {'Yes' if os.getenv('VIRUSTOTAL_API_KEY') else 'No'}")
print(f"ABUSE_KEY: {'Yes' if os.getenv('ABUSEIPDB_API_KEY') else 'No'}")

from app.engine.urls import analyze_urls
from app.engine.content import analyze_content
from app.engine.explainability import extract_snippets
from app.database import get_db, init_db
from app.models import Analysis, User
from app.auth import (
    get_password_hash, authenticate_user, create_access_token, 
    get_current_user, ACCESS_TOKEN_EXPIRE_MINUTES
)
from app.engine.threat_intel import run_threat_intel
from datetime import timedelta
from app.report_generator import generate_pdf_report
from fastapi.responses import Response

from app.engine.headers import analyze_headers
from app.engine.brand import analyze_brands
from app.engine.ioc import extract_iocs
from app.engine.aggregator import aggregate_risk, generate_summary
from app.engine.models import Finding, Severity, AnalysisContext
from app.engine.domain_intel import enrich_domain, generate_domain_findings
from app.engine.postprocess import group_findings
from app.engine.mitre import map_to_mitre
from app.dashboard import get_dashboard_stats

app = FastAPI(title="PhishGuard Engine", version="0.4.0")
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", None)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Models ---
class EmailRequest(BaseModel):
    email: str

class AnalysisResponse(BaseModel):
    riskScore: int
    riskLevel: str
    findings: List[Finding]
    highlightedSnippets: Optional[List[dict]] = None

class HistoryResponse(BaseModel):
    id: int
    riskScore: int
    riskLevel: str
    findings: List[dict]
    email_content: str
    created_at: str

class DashboardStats(BaseModel):
    total_analyses: int
    average_risk_score: float
    risk_distribution: dict
    top_brands: List[dict]
    top_attack_types: List[dict]
    today_count: int
    this_week_count: int
    recent_attacks: List[dict]
    trend_over_time: List[dict]
    mitre_coverage: List[dict]

class UserCreate(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str


# --- Routes ---
@app.on_event("startup")
async def startup():
    await init_db()

@app.get("/")
def root():
    return {"message": "PhishGuard Engine is running"}
@app.post("/analyze", response_model=AnalysisResponse)
async def analyze_email(
    request: EmailRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    email_text = request.email
    
    # --- 1. Initialize context ---
    context = AnalysisContext(email_content=email_text)
    
    # --- 2. Extract URLs for other modules ---
    from app.engine.urls import extract_urls
    context.urls = extract_urls(email_text)
    
    # --- 3. Run all analysis modules ---
    all_findings = []
    
    # 3a. Header Analysis
    header_findings, header_context = analyze_headers(email_text)
    all_findings.extend(header_findings)
    context.headers = header_context.headers
    context.spf_result = header_context.spf_result
    context.dkim_result = header_context.dkim_result
    context.dmarc_result = header_context.dmarc_result
    
    # 3b. URL Analysis (existing)
    url_findings = analyze_urls(email_text)
    for f in url_findings:
        all_findings.append(Finding(
            module="URL Analysis",
            category=f["category"],
            severity=Severity(f["severity"]),
            description=f["description"],
            mitre_technique="T1566.002"
        ))
    
    # 3c. Content Analysis (existing BART)
    content_findings = analyze_content(email_text)
    for f in content_findings:
        all_findings.append(Finding(
            module="Content Analysis (AI)",
            category=f["category"],
            severity=Severity(f["severity"]),
            description=f["description"],
            mitre_technique="T1566.002"
        ))
        
    for url in context.urls:
        domain_match = re.search(r'https?://([^/]+)', url)
        if domain_match:
            domain = domain_match.group(1)
            info = enrich_domain(domain, VT_API_KEY)
            domain_findings = generate_domain_findings(info)
            all_findings.extend(domain_findings)
            context.domains.append(domain)
    
    # 3d. Brand Detection
    brand_findings = analyze_brands(email_text, context.urls, context)
    all_findings.extend(brand_findings)
    
    # 3e. IOC Extraction
    ioc_findings = extract_iocs(email_text, context)
    all_findings.extend(ioc_findings)


    ti_findings = await run_threat_intel(context)
    all_findings.extend(ti_findings)
    
    # --- 4. Aggregate Risk ---
    risk_score, risk_level = aggregate_risk(all_findings)
    
    # --- 5. Generate Summary (for the response) ---
    summary = generate_summary(all_findings)

    all_findings = group_findings(all_findings, email_text, context.urls)
    
    # Convert findings to the format expected by the frontend

    print(f"[MAIN] After grouping: {len(all_findings)} findings")
    for i, f in enumerate(all_findings):
        print(f"  [{i}] {f.category} (module: {f.module})")
        
    for f in all_findings:
        mitre_info = map_to_mitre(f.category)
        f.type = mitre_info.get("type", "evidence")
        if f.type == "technique":
            f.mitre_technique = mitre_info.get("technique_id")
            f.mitre_tactic = mitre_info.get("tactic")
            f.mitre_url = mitre_info.get("url")
        else:
            f.mitre_technique = None
            f.mitre_tactic = None
            f.mitre_url = None

    findings_response = []
    for f in all_findings:
        if hasattr(f.severity, 'value'):
            severity_str = f.severity.value
        else:
            severity_str = str(f.severity)
        
        findings_response.append({
            "category": f.category,
            "severity": severity_str,
            "description": f.description,
            "evidence": getattr(f, 'evidence', None),
            "confidence": getattr(f, 'confidence', None),
            "mitre_technique": getattr(f, 'mitre_technique', None),
            "mitre_tactic": getattr(f, 'mitre_tactic', None),
            "mitre_url": getattr(f, 'mitre_url', None),
            "module": f.module,
            "type": f.type,  # Add this
        })

    print(f"[MAIN] After building findings_response: {len(findings_response)} items")
            
    findings_dict = []
    for f in all_findings:
        # Convert severity to string (handles both enum and str)
        if hasattr(f.severity, 'value'):
            severity_str = f.severity.value
        else:
            severity_str = str(f.severity)
        
        findings_dict.append({
            "category": f.category,
            "severity": severity_str,
            "description": f.description
        })

    findings_for_db = []
    for f in all_findings:
        if hasattr(f.severity, 'value'):
            severity_str = f.severity.value
        else:
            severity_str = str(f.severity)
        findings_for_db.append({
            "category": f.category,
            "severity": severity_str,
            "description": f.description
        })
        
    # --- 6. Extract highlights (existing) ---
    from app.engine.explainability import extract_snippets
    highlighted_snippets = extract_snippets(email_text, findings_dict)
    
    # --- 7. Save to database ---
    # Extract brand and attack type for stats
    brand_impersonated = None
    attack_type = None
    for f in all_findings:
        if "impersonates" in f.description.lower():
            parts = f.description.split("'")
            if len(parts) > 1:
                brand_impersonated = parts[1].lower()
        if "AI detected" in f.description:
            if "credential" in f.description.lower():
                attack_type = "credential_harvesting"
            elif "urgency" in f.description.lower():
                attack_type = "urgency_manipulation"
            elif "financial" in f.description.lower():
                attack_type = "financial_scam"
            elif "personal information" in f.description.lower():
                attack_type = "data_harvesting"
    
    # Only save if it's not a "safe" email
    if risk_level != Severity.LOW and risk_level != Severity.INFO:
        db_analysis = Analysis(
            user_id=current_user.id,
            email_content=email_text,
            risk_score=risk_score,
            risk_level=risk_level.value,
            findings=findings_for_db,
            highlighted_snippets=highlighted_snippets,
            brand_impersonated=brand_impersonated,
            attack_type=attack_type
        )
        db.add(db_analysis)
        await db.commit()
        await db.refresh(db_analysis)

    print(f"[MAIN] Before return - findings_response has {len(findings_response)} items:")
    for i, f in enumerate(findings_response):
        print(f"  [{i}] {f['category']} ({f['severity']})")
    print(f"[MAIN] Highlighted snippets: {len(highlighted_snippets)}")
    
    # --- 8. Return response ---
    return AnalysisResponse(
        riskScore=risk_score,
        riskLevel=risk_level.value,
        findings=findings_response,
        highlightedSnippets=highlighted_snippets
    )

@app.get("/history", response_model=List[HistoryResponse])
async def get_history(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    result = await db.execute(
        select(Analysis)
        .where(Analysis.user_id == current_user.id)
        .order_by(desc(Analysis.created_at))
        .limit(100)
    )
    analyses = result.scalars().all()
    
    return [
        {
            "id": a.id,
            "riskScore": a.risk_score,
            "riskLevel": a.risk_level,
            "findings": a.findings,
            "email_content": a.email_content,
            "created_at": a.created_at.isoformat()
        }
        for a in analyses
    ]

@app.get("/report/{analysis_id}")
async def download_report(analysis_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Generate and download a PDF report for a specific analysis ID."""
    result = await db.execute(select(Analysis).where(Analysis.id == analysis_id,  Analysis.user_id == current_user.id ))
    analysis = result.scalar_one_or_none()
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    
    # Prepare data for the report generator
    data = {
        "id": analysis.id,
        "riskScore": analysis.risk_score,
        "riskLevel": analysis.risk_level,
        "findings": analysis.findings,
        "highlights": analysis.highlighted_snippets,
    }
    
    pdf_bytes = generate_pdf_report(data, analysis.email_content)
    
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=phishguard_report_{analysis_id}.pdf"
        }
    )

@app.get("/dashboard/stats", response_model=DashboardStats)
async def get_dashboard_stats_endpoint(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    stats = await get_dashboard_stats(db, current_user.id)
    return stats

@app.post("/register")
async def register(user: UserCreate, db: AsyncSession = Depends(get_db)):
    existing = await db.execute(select(User).where(User.username == user.username))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Username already registered")
    
    hashed = get_password_hash(user.password)
    new_user = User(username=user.username, hashed_password=hashed)
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)
    return {"message": "User created successfully"}

@app.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(get_db)):
    user = await authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}