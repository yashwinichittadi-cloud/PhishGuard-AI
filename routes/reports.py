"""
PhishGuard AI - Report Generation Route & PDF Exporter
Generates institutional-grade PDF security audits using ReportLab.
"""

import io
from flask import Blueprint, send_file, abort, current_app
from database.db import get_scan_by_id

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

reports_bp = Blueprint("reports", __name__)


def generate_pdf_report(scan: dict) -> io.BytesIO:
    """Creates a styled, publication-ready PDF audit report for a given scan."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()

    # Custom styles
    brand_title_style = ParagraphStyle(
        "BrandTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0f172a"),
        alignment=TA_LEFT
    )

    brand_subtitle_style = ParagraphStyle(
        "BrandSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#64748b"),
        alignment=TA_LEFT
    )

    section_heading = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#0284c7"),
        spaceBefore=10,
        spaceAfter=6
    )

    body_style = ParagraphStyle(
        "BodyDark",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#334155")
    )

    badge_style = ParagraphStyle(
        "BadgeText",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=11,
        leading=14,
        alignment=TA_CENTER
    )

    story = []

    # 1. Header Banner
    header_data = [
        [
            Paragraph("🛡️ <b>PHISHGUARD AI</b>", brand_title_style),
            Paragraph(f"<b>Scan ID:</b> #{scan.get('scan_uuid', scan['id'])}<br/><b>Generated:</b> {scan.get('created_at')}", ParagraphStyle("HeaderMeta", parent=styles["Normal"], fontName="Helvetica", fontSize=8, leading=11, alignment=TA_RIGHT, textColor=colors.HexColor("#475569")))
        ],
        [
            Paragraph("Intelligent Phishing Detection & Cybersecurity Analysis Platform", brand_subtitle_style),
            Paragraph("Defensive Local URL Audit", ParagraphStyle("HeaderSubMeta", parent=styles["Normal"], fontName="Helvetica-Oblique", fontSize=8, leading=10, alignment=TA_RIGHT, textColor=colors.HexColor("#64748b")))
        ]
    ]
    header_table = Table(header_data, colWidths=[340, 200])
    header_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
    ]))
    story.append(header_table)
    story.append(Spacer(1, 8))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284c7"), spaceAfter=12))

    # 2. Status Banner Color Selection
    slug = scan.get("classification_slug", "safe")
    if slug == "safe":
        bg_col = colors.HexColor("#d1fae5")
        text_col = colors.HexColor("#065f46")
        border_col = colors.HexColor("#10b981")
    elif slug == "suspicious":
        bg_col = colors.HexColor("#fef3c7")
        text_col = colors.HexColor("#92400e")
        border_col = colors.HexColor("#f59e0b")
    else:
        bg_col = colors.HexColor("#fee2e2")
        text_col = colors.HexColor("#991b1b")
        border_col = colors.HexColor("#ef4444")

    verdict_text = f"<b>CLASSIFICATION VERDICT: {scan.get('classification', 'ANALYZED').upper()}</b> (Risk Score: {scan.get('risk_score', 0)}/100)"
    verdict_p = Paragraph(f"<font color='{text_col.hexval()}'>{verdict_text}</font>", badge_style)
    verdict_table = Table([[verdict_p]], colWidths=[540])
    verdict_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), bg_col),
        ("BOX", (0, 0), (-1, -1), 1.5, border_col),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
    ]))
    story.append(verdict_table)
    story.append(Spacer(1, 10))

    # 3. Target URL Overview Table
    story.append(Paragraph("TARGET URL AUDIT OVERVIEW", section_heading))
    overview_data = [
        [Paragraph("<b>Submitted URL:</b>", body_style), Paragraph(f"<font name='Courier'>{scan.get('submitted_url')}</font>", body_style)],
        [Paragraph("<b>Extracted Domain:</b>", body_style), Paragraph(f"<b>{scan.get('domain', 'N/A')}</b>", body_style)],
        [Paragraph("<b>AI / ML Model Used:</b>", body_style), Paragraph(str(scan.get("model_name", "Trained ML Model")), body_style)],
        [Paragraph("<b>Execution Mode:</b>", body_style), Paragraph(str(scan.get("model_mode", "Local Analysis")), body_style)],
        [Paragraph("<b>Analysis Timestamp:</b>", body_style), Paragraph(str(scan.get("created_at")), body_style)]
    ]
    overview_table = Table(overview_data, colWidths=[130, 410])
    overview_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(overview_table)
    story.append(Spacer(1, 10))

    # 4. Quantitative Feature Analysis
    story.append(Paragraph("QUANTITATIVE FEATURE EXTRACTION", section_heading))
    feats = scan.get("feature_analysis", {})
    feat_rows = [
        [Paragraph("<b>Feature Metric</b>", body_style), Paragraph("<b>Observed Value</b>", body_style), Paragraph("<b>Threat Interpretation</b>", body_style)],
        [Paragraph("URL Length", body_style), Paragraph(str(feats.get("url_len", len(scan.get("submitted_url", "")))), body_style), Paragraph("Lengths > 75 chars often hide fraudulent subdomains.", body_style)],
        [Paragraph("Host / Domain Length", body_style), Paragraph(str(feats.get("domain_len", "N/A")), body_style), Paragraph("Long domains frequently incorporate typosquatted terms.", body_style)],
        [Paragraph("Subdomain Levels", body_style), Paragraph(str(feats.get("subdomain_count", 0)), body_style), Paragraph("Subdomains >= 3 mimic corporate infrastructures.", body_style)],
        [Paragraph("Dot ('.') Count", body_style), Paragraph(str(feats.get("dot_count", 0)), body_style), Paragraph("Elevated dots indicate deep nested routing.", body_style)],
        [Paragraph("Hyphen ('-') Count", body_style), Paragraph(str(feats.get("hyphen_count", 0)), body_style), Paragraph("Multiple hyphens concatenate spoofed brands.", body_style)],
        [Paragraph("IP Address Host", body_style), Paragraph("YES" if feats.get("is_ip") else "NO", body_style), Paragraph("Bare IP addresses are a critical phishing indicator.", body_style)],
        [Paragraph("HTTPS Scheme", body_style), Paragraph("YES" if feats.get("is_https") else "NO", body_style), Paragraph("Note: Over 80% of phishing sites also use HTTPS.", body_style)],
        [Paragraph("Credential '@' Symbol", body_style), Paragraph("DETECTED" if feats.get("has_at_symbol") else "NONE", body_style), Paragraph("Used to bypass URL host parsing in browsers.", body_style)],
        [Paragraph("URL Shortener Service", body_style), Paragraph("YES" if feats.get("is_shortener") else "NO", body_style), Paragraph("Conceals real destination landing servers.", body_style)],
    ]
    feat_table = Table(feat_rows, colWidths=[130, 90, 320])
    feat_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e0f2fe")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#0369a1")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
    ]))
    story.append(feat_table)
    story.append(Spacer(1, 10))

    # 5. Key Threat Intelligence Findings
    findings = scan.get("findings", [])
    if findings:
        story.append(Paragraph("KEY HEURISTIC FINDINGS & EXPLAINABILITY", section_heading))
        finding_rows = [[Paragraph("<b>Finding</b>", body_style), Paragraph("<b>Severity Weight</b>", body_style), Paragraph("<b>Detailed Explanation</b>", body_style)]]
        for f in findings:
            weight_text = f"+{f.get('weight', 0)} pts" if f.get("weight") else "0 pts"
            finding_rows.append([
                Paragraph(f"<b>{f.get('feature', 'Finding')}</b>", body_style),
                Paragraph(weight_text, body_style),
                Paragraph(f.get("description", ""), body_style)
            ])
        f_table = Table(finding_rows, colWidths=[150, 80, 310])
        f_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(f_table)
        story.append(Spacer(1, 10))

    # 6. Safety Recommendations
    recommendations = scan.get("recommendations", [])
    if recommendations:
        story.append(Paragraph("RECOMMENDED DEFENSIVE ACTIONS", section_heading))
        rec_items = []
        for r in recommendations:
            rec_items.append([Paragraph("•", body_style), Paragraph(r, body_style)])
        rec_table = Table(rec_items, colWidths=[15, 525])
        rec_table.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]))
        story.append(rec_table)
        story.append(Spacer(1, 12))

    # 7. Academic & Security Notice Footer
    notice_text = (
        "<b>ACADEMIC & OPERATIONAL NOTICE:</b> This audit report was produced locally by PhishGuard AI via "
        "lexical string analysis and trained character n-gram machine learning. In compliance with cybersecurity "
        "safeguards, <b>the submitted URL was never contacted, crawled, or requested over the network</b>. "
        "This platform is designed for defensive educational awareness and threat triage."
    )
    notice_p = Paragraph(notice_text, ParagraphStyle("NoticeStyle", parent=styles["Normal"], fontName="Helvetica", fontSize=7.5, leading=10, textColor=colors.HexColor("#64748b")))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#94a3b8"), spaceAfter=6))
    story.append(notice_p)

    doc.build(story)
    buffer.seek(0)
    return buffer


@reports_bp.route("/api/reports/download/<int:scan_id>")
def download_pdf(scan_id):
    """API endpoint delivering the generated PDF document."""
    scan = get_scan_by_id(scan_id)
    if not scan:
        abort(404, description="Scan record not found.")

    pdf_buffer = generate_pdf_report(scan)
    filename = f"PhishGuard_Report_{scan.get('scan_uuid', scan_id)}.pdf"

    return send_file(
        pdf_buffer,
        as_attachment=True,
        download_name=filename,
        mimetype="application/pdf"
    )
