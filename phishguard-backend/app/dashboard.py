# app/dashboard.py
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_
from datetime import datetime, timedelta
from app.models import Analysis
from typing import Dict, List, Any

async def get_dashboard_stats(db: AsyncSession, user_id: int) -> Dict[str, Any]:
    today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    start_of_week = today - timedelta(days=today.weekday())
    
    # Counts
    total_count = await db.scalar(select(func.count()).where(Analysis.user_id == user_id))
    today_count = await db.scalar(select(func.count()).where(and_(Analysis.user_id == user_id, Analysis.created_at >= today)))
    week_count = await db.scalar(select(func.count()).where(and_(Analysis.user_id == user_id, Analysis.created_at >= start_of_week)))
    
    # Average risk score
    avg_score = await db.scalar(select(func.avg(Analysis.risk_score)).where(Analysis.user_id == user_id)) or 0.0
    
    # Risk distribution
    levels = ["Critical", "High", "Medium", "Low"]
    risk_dist = {}
    for level in levels:
        count = await db.scalar(select(func.count()).where(and_(Analysis.user_id == user_id, Analysis.risk_level == level)))
        risk_dist[level] = count or 0
    
    # Top brands
    brand_result = await db.execute(
        select(Analysis.brand_impersonated, func.count(Analysis.id))
        .where(and_(Analysis.user_id == user_id, Analysis.brand_impersonated.isnot(None)))
        .group_by(Analysis.brand_impersonated)
        .order_by(func.count(Analysis.id).desc())
        .limit(5)
    )
    top_brands = [{"brand": row[0], "count": row[1]} for row in brand_result.all()]
    
    # Top attack types
    attack_result = await db.execute(
        select(Analysis.attack_type, func.count(Analysis.id))
        .where(and_(Analysis.user_id == user_id, Analysis.attack_type.isnot(None)))
        .group_by(Analysis.attack_type)
        .order_by(func.count(Analysis.id).desc())
        .limit(5)
    )
    top_attacks = [{"type": row[0], "count": row[1]} for row in attack_result.all()]
    
    # Recent attacks
    recent_result = await db.execute(
        select(Analysis)
        .where(Analysis.user_id == user_id)
        .order_by(Analysis.created_at.desc())
        .limit(5)
    )
    recent_attacks = []
    for a in recent_result.scalars().all():
        recent_attacks.append({
            "id": a.id,
            "risk_score": a.risk_score,
            "risk_level": a.risk_level,
            "created_at": a.created_at.isoformat(),
            "brand_impersonated": a.brand_impersonated,
            "attack_type": a.attack_type,
            "findings_count": len(a.findings),
        })
    
    # Trend over time (last 30 days)
    trend = []
    for i in range(30, -1, -1):
        day = (datetime.now() - timedelta(days=i)).date()
        start = datetime.combine(day, datetime.min.time())
        end = datetime.combine(day, datetime.max.time())
        count = await db.scalar(select(func.count()).where(and_(Analysis.user_id == user_id, Analysis.created_at >= start, Analysis.created_at <= end)))
        avg_risk = await db.scalar(select(func.avg(Analysis.risk_score)).where(and_(Analysis.user_id == user_id, Analysis.created_at >= start, Analysis.created_at <= end))) or 0.0
        trend.append({
            "date": day.isoformat(),
            "count": count or 0,
            "avg_risk": round(avg_risk, 1)
        })
    
    # MITRE coverage: scan all findings to collect tactics
    tactic_counts = {}
    analyses_result = await db.execute(
        select(Analysis.findings).where(Analysis.user_id == user_id)
    )
    for row in analyses_result.scalars().all():
        for finding in row:
            tactic = finding.get('mitre_tactic')
            if tactic:
                tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1
    
    mitre_coverage = [{"tactic": k, "count": v} for k, v in tactic_counts.items()]
    
    return {
        "total_analyses": total_count or 0,
        "average_risk_score": round(avg_score, 1),
        "risk_distribution": risk_dist,
        "top_brands": top_brands,
        "top_attack_types": top_attacks,
        "today_count": today_count or 0,
        "this_week_count": week_count or 0,
        "recent_attacks": recent_attacks,
        "trend_over_time": trend,
        "mitre_coverage": mitre_coverage,
    }