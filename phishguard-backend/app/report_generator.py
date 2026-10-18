# app/report_generator.py
import re
import io
from datetime import datetime
from typing import List, Dict, Any
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.graphics.shapes import Drawing, Rect, String, Line
from reportlab.graphics import renderPDF

# ----- Helper Functions -----
def _format_attack_type(attack_type: str) -> str:
    """Format attack type labels: data_harvesting → Data Harvesting"""
    map_labels = {
        "credential_harvesting": "Credential Harvesting",
        "data_harvesting": "Data Harvesting",
        "financial_scam": "Financial Scam",
        "urgency_manipulation": "Urgency Manipulation",
        "brand_impersonation": "Brand Impersonation"
    }
    return map_labels.get(attack_type, attack_type.replace('_', ' ').title())

def _format_brand(brand: str) -> str:
    """Format brand names: paypal → PayPal"""
    map_brands = {
        "paypal": "PayPal",
        "microsoft": "Microsoft",
        "google": "Google",
        "amazon": "Amazon",
        "apple": "Apple",
        "facebook": "Facebook",
        "linkedin": "LinkedIn"
    }
    return map_brands.get(brand, brand.title())

def _get_severity_color(severity: str) -> str:
    colors_map = {
        "Critical": "#dc2626",
        "High": "#f97316",
        "Medium": "#eab308",
        "Low": "#3b82f6",
        "Info": "#6b7280"
    }
    return colors_map.get(severity, "#6b7280")

# ----- Main Report Generator -----
def generate_pdf_report(analysis: Dict[str, Any], email_content: str) -> bytes:
    """Generate a professional PDF report for a given analysis."""
    
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=72,
        leftMargin=72,
        topMargin=72,
        bottomMargin=72,
    )
    
    styles = getSampleStyleSheet()
    
    # --- Custom Styles ---
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Title'],
        fontSize=24,
        textColor=colors.HexColor('#1e3a8a'),
        alignment=TA_CENTER,
        spaceAfter=6
    )
    subtitle_style = ParagraphStyle(
        'Subtitle',
        parent=styles['Normal'],
        fontSize=12,
        textColor=colors.grey,
        alignment=TA_CENTER,
        spaceAfter=12
    )
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=colors.HexColor('#1e40af'),
        spaceAfter=6,
        spaceBefore=12,
        borderWidth=0,
        borderColor=colors.HexColor('#1e40af'),
        borderPadding=0,
        leftIndent=0,
    )
    normal_style = ParagraphStyle(
        'CustomNormal',
        parent=styles['Normal'],
        fontSize=10,
        leading=14
    )
    score_style = ParagraphStyle(
        'ScoreStyle',
        parent=styles['Normal'],
        fontSize=48,
        leading=52,
        textColor=colors.HexColor('#dc2626'),
        alignment=TA_CENTER,
        spaceBefore=-6,
        spaceAfter=-4
    )
    small_style = ParagraphStyle(
        'Small',
        parent=styles['Normal'],
        fontSize=8,
        textColor=colors.grey,
        alignment=TA_CENTER
    )
    
    story = []
    
    # ----- HEADER -----
    story.append(Paragraph("PHISHGUARD", title_style))
    story.append(Paragraph("Security Analysis Report", subtitle_style))
    story.append(Spacer(1, 0.1 * inch))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#1e3a8a')))
    story.append(Spacer(1, 0.2 * inch))
    
    # Meta info
    report_id = f"#PG-{analysis['id']:06d}"
    timestamp = datetime.now().strftime("%B %d, %Y at %I:%M %p")
    story.append(Paragraph(f"<b>Report ID:</b> {report_id}", normal_style))
    story.append(Paragraph(f"<b>Generated:</b> {timestamp}", normal_style))
    story.append(Spacer(1, 0.2 * inch))
    
    # ----- 1. EXECUTIVE SUMMARY -----
    story.append(Paragraph("1. Executive Summary", heading_style))
    risk_level = analysis['riskLevel']
    risk_score = analysis['riskScore']
    
    if risk_level == "Critical":
        summary = (f"The analyzed email exhibits <b>Critical</b> risk indicators (Score: {risk_score}%). "
                   f"Multiple high-severity threats were identified, including suspicious URLs and credential harvesting. "
                   f"We strongly advise against interacting with this email or any embedded links.")
    elif risk_level == "High":
        summary = (f"The analyzed email exhibits <b>High</b> risk indicators (Score: {risk_score}%). "
                   f"Several phishing tactics were detected. Exercise extreme caution and verify the sender's identity.")
    elif risk_level == "Medium":
        summary = (f"The analyzed email exhibits <b>Medium</b> risk indicators (Score: {risk_score}%). "
                   f"Some suspicious elements were found. Proceed with caution.")
    else:
        summary = (f"The analyzed email exhibits <b>Low</b> risk indicators (Score: {risk_score}%). "
                   f"No major phishing indicators were detected, but remain vigilant.")
    story.append(Paragraph(summary, normal_style))
    story.append(Spacer(1, 0.2 * inch))
    
    # ----- 2. OVERALL RISK SCORE (with gauge) -----
    story.append(Paragraph("2. Overall Risk Score", heading_style))
    # Big number
    story.append(Paragraph(f"{risk_score}%", score_style))
    
    # Gauge: a coloured bar with a needle or just a progress bar
    # We'll create a simple drawing with a rectangle and a label
   # Gauge: just a simple progress bar (no text inside)
    d = Drawing(400, 20)
    # Background bar
    d.add(Rect(0, 0, 400, 14, fillColor=colors.lightgrey, strokeColor=None))
    # Fill based on score
    fill_color = colors.HexColor('#dc2626') if risk_score > 70 else colors.HexColor('#f97316') if risk_score > 40 else colors.HexColor('#eab308')
    bar_width = (risk_score / 100) * 400
    d.add(Rect(0, 0, bar_width, 14, fillColor=fill_color, strokeColor=None))
    story.append(d)
    
    # ----- 3. ATTACK TECHNIQUES (MITRE) -----
    # Separate findings into techniques and evidence
    techniques = [f for f in analysis['findings'] if f.get('type') == 'technique' and f.get('mitre_technique')]
    evidence = [f for f in analysis['findings'] if not (f.get('type') == 'technique' and f.get('mitre_technique'))]
    
    if techniques:
        story.append(Paragraph("3. Attack Techniques (MITRE ATT&CK)", heading_style))
        for f in techniques:
            severity_color = _get_severity_color(f['severity'])
            bullet = (f"<b>{f['category']}</b> (Severity: <font color='{severity_color}'>{f['severity']}</font>)<br/>"
                      f"{f['description']}<br/>"
                      f"<font color='#1e40af'><b>MITRE:</b> {f.get('mitre_technique', 'N/A')} - {f.get('mitre_tactic', '')}</font>")
            story.append(Paragraph(f"• {bullet}", normal_style))
            story.append(Spacer(1, 0.05 * inch))
        story.append(Spacer(1, 0.1 * inch))
    
    # ----- 4. SUPPORTING EVIDENCE -----
    if evidence:
        story.append(Paragraph("4. Supporting Evidence", heading_style))
        for f in evidence:
            severity_color = _get_severity_color(f['severity'])
            bullet = f"<b>{f['category']}</b> (Severity: <font color='{severity_color}'>{f['severity']}</font>)<br/>{f['description']}"
            story.append(Paragraph(f"• {bullet}", normal_style))
            story.append(Spacer(1, 0.05 * inch))
        story.append(Spacer(1, 0.1 * inch))
    
    # ----- 5. INDICATORS OF COMPROMISE (IOCs) -----
    iocs = analysis.get('iocs', {})
    if iocs and any(iocs.values()):
        story.append(Paragraph("5. Indicators of Compromise (IOCs)", heading_style))
        # Build a table with Type and Values
        ioc_data = [["Type", "Values"]]
        for ioc_type, values in iocs.items():
            if values:
                # Format type label
                type_label = ioc_type.replace('_', ' ').title()
                # For hashes, we have a dict, so handle specially
                if ioc_type == "hashes":
                    for hash_type, hash_values in values.items():
                        if hash_values:
                            ioc_data.append([f"{type_label} ({hash_type.upper()})", ", ".join(hash_values[:5])])
                else:
                    ioc_data.append([type_label, ", ".join(values[:5])])
        if len(ioc_data) > 1:
            ioc_table = Table(ioc_data, colWidths=[100, 250])
            ioc_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e3a8a')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
                ('PADDING', (0, 0), (-1, -1), 4),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ]))
            story.append(ioc_table)
        else:
            story.append(Paragraph("No IOCs detected.", normal_style))
        story.append(Spacer(1, 0.2 * inch))
    
    # ----- 6. URLS FOUND -----
    story.append(Paragraph("6. URLs Found", heading_style))
    urls = re.findall(r'https?://[^\s<>"\'\)]+', email_content)
    if urls:
        for url in urls:
            story.append(Paragraph(f"• {url}", normal_style))
    else:
        story.append(Paragraph("No URLs detected in this email.", normal_style))
    story.append(Spacer(1, 0.2 * inch))
    
    # ----- 7. SUSPICIOUS PHRASES -----
    story.append(Paragraph("7. Suspicious Phrases", heading_style))
    highlights = analysis.get('highlights', [])
    if highlights:
        # Extract sentences containing suspicious keywords
        suspicious_keywords = [
            "urgent", "immediate", "verify", "confirm", "password",
            "account", "suspended", "paypal", "microsoft", "google",
            "unusual activity", "security alert", "click here"
        ]
        sentences = []
        sentence_splits = re.split(r'(?<=[.!?])\s+', email_content)
        for sentence in sentence_splits:
            sentence_lower = sentence.lower()
            if any(kw in sentence_lower for kw in suspicious_keywords):
                clean = sentence.strip()
                if len(clean) > 5:
                    sentences.append(clean)
        # Deduplicate
        seen = set()
        unique_sentences = []
        for s in sentences:
            key = s[:50].lower()
            if key not in seen:
                seen.add(key)
                unique_sentences.append(s)
        if unique_sentences:
            for sent in unique_sentences[:10]:
                if len(sent) > 80:
                    sent = sent[:77] + "..."
                story.append(Paragraph(f"• \"{sent}\"", normal_style))
            if len(unique_sentences) > 10:
                story.append(Paragraph(f"• ... and {len(unique_sentences)-10} more.", normal_style))
        else:
            story.append(Paragraph("No suspicious phrases detected.", normal_style))
    else:
        story.append(Paragraph("No suspicious phrases detected.", normal_style))
    story.append(Spacer(1, 0.2 * inch))
    
    # ----- 8. RECOMMENDED ACTIONS -----
    story.append(Paragraph("8. Recommended Actions", heading_style))
    if risk_level in ["Critical", "High"]:
        actions = [
            "Do NOT click any links or download attachments.",
            "Do NOT reply to the sender or provide any personal information.",
            "Report this email to your IT/Security team immediately.",
            "If you already interacted with this email, contact your security team urgently."
        ]
    elif risk_level == "Medium":
        actions = [
            "Exercise caution before clicking links or opening attachments.",
            "Verify the sender's email address and domain carefully.",
            "Report to IT if you are unsure."
        ]
    else:
        actions = [
            "No immediate action required, but always remain cautious.",
            "Continue to monitor for suspicious activity."
        ]
    for i, action in enumerate(actions, 1):
        story.append(Paragraph(f"{i}. {action}", normal_style))
    story.append(Spacer(1, 0.2 * inch))
    
    # ----- 9. ANALYST NOTES -----
    story.append(Paragraph("9. Analyst Notes", heading_style))
    story.append(Paragraph("______________________________________________________________________________", normal_style))
    story.append(Spacer(1, 0.5 * inch))
    story.append(Paragraph("______________________________________________________________________________", normal_style))
    story.append(Spacer(1, 0.1 * inch))
    story.append(Paragraph("<i>Optional: Add internal investigation notes here.</i>", normal_style))
    
    # ----- FOOTER -----
    story.append(Spacer(1, 0.5 * inch))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.grey))
    story.append(Paragraph(
        f"<font size='8' color='grey'>This report was automatically generated by PhishGuard v1.0.0 • {timestamp}</font>",
        small_style
    ))
    
    # Build PDF
    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()