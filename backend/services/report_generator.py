import os
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from backend.database.schema import get_db

def generate_pdf_audit_report(output_path: str = None) -> str:
    """Generates an executive, formal Cybersecurity Audit and Permission Creep Report"""
    if not output_path:
        reports_dir = os.path.join(os.path.dirname(__file__), "..", "..", "reports")
        os.makedirs(reports_dir, exist_ok=True)
        filename = f"PermissionGuard_Audit_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        output_path = os.path.join(reports_dir, filename)

    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=colors.HexColor('#1e293b')
    )
    subtitle_style = ParagraphStyle(
        'DocSubTitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#64748b')
    )
    h2_style = ParagraphStyle(
        'SectionHeading',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=13,
        leading=17,
        textColor=colors.HexColor('#0f172a'),
        spaceBefore=14,
        spaceAfter=6
    )
    body_style = ParagraphStyle(
        'Body',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor('#334155')
    )
    bold_body = ParagraphStyle(
        'BoldBody',
        parent=body_style,
        fontName='Helvetica-Bold'
    )

    story = []

    # Header / Title
    story.append(Paragraph("PermissionGuard — Access Governance & Creep Audit Report", title_style))
    story.append(Spacer(1, 4))
    story.append(Paragraph(f"Generated on {datetime.now().strftime('%B %d, %Y at %H:%M:%S UTC')} | Classification: INTERNAL SECURITY AUDIT", subtitle_style))
    story.append(Spacer(1, 8))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#0284c7'), spaceBefore=2, spaceAfter=12))

    # Pull metrics from database
    with get_db() as conn:
        cursor = conn.cursor()
        
        cursor.execute("SELECT count(*) as cnt FROM users")
        total_users = cursor.fetchone()["cnt"]
        
        cursor.execute("SELECT count(*) as cnt FROM resources")
        total_resources = cursor.fetchone()["cnt"]
        
        cursor.execute("SELECT count(*) as cnt FROM permissions WHERE status = 'ACTIVE'")
        active_perms = cursor.fetchone()["cnt"]
        
        cursor.execute("SELECT count(*) as cnt FROM permissions WHERE status = 'INACTIVE'")
        inactive_perms = cursor.fetchone()["cnt"]
        
        cursor.execute("SELECT count(*) as cnt FROM permissions WHERE status = 'EXPIRED'")
        expired_perms = cursor.fetchone()["cnt"]
        
        cursor.execute("SELECT count(*) as cnt FROM security_findings WHERE status = 'OPEN' AND risk_level IN ('HIGH', 'CRITICAL')")
        high_risk_findings = cursor.fetchone()["cnt"]

        # 1. Executive Summary
        story.append(Paragraph("1. Executive Summary", h2_style))
        exec_text = (
            "This report provides an automated point-in-time analysis of the organizational permission lifecycle, "
            "identifying potential permission creep, dormant credentials, role mismatches, and access accumulation. "
            "The PermissionGuard rules-based detection engine continuously assesses active authorizations against "
            "the principle of least privilege to prevent excessive exposure of sensitive company assets."
        )
        story.append(Paragraph(exec_text, body_style))
        story.append(Spacer(1, 8))

        # Metrics Table
        metrics_data = [
            [
                Paragraph(f"<b>Total Monitored Users:</b> {total_users}", body_style),
                Paragraph(f"<b>Protected Resources:</b> {total_resources}", body_style),
                Paragraph(f"<b>Active Permissions:</b> {active_perms}", body_style)
            ],
            [
                Paragraph(f"<b>Inactive (Dormant):</b> {inactive_perms}", body_style),
                Paragraph(f"<b>Expired Grants:</b> {expired_perms}", body_style),
                Paragraph(f"<b>High/Critical Findings:</b> <font color='#b91c1c'><b>{high_risk_findings}</b></font>", body_style)
            ]
        ]
        t_metrics = Table(metrics_data, colWidths=[175, 175, 180])
        t_metrics.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8fafc')),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#cbd5e1')),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
            ('TOPPADDING', (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('LEFTPADDING', (0,0), (-1,-1), 8),
            ('RIGHTPADDING', (0,0), (-1,-1), 8)
        ]))
        story.append(t_metrics)
        story.append(Spacer(1, 14))

        # 2. High & Critical Security Findings
        story.append(Paragraph("2. Prioritized Security Findings (High / Critical)", h2_style))
        cursor.execute("""
            SELECT f.finding_code, u.full_name, r.name as role_name, res.name as res_name,
                   f.risk_level, f.risk_score, f.what_happened, f.recommended_action
            FROM security_findings f
            JOIN users u ON f.user_id = u.id
            JOIN roles r ON u.role_id = r.id
            JOIN resources res ON f.resource_id = res.id
            WHERE f.status = 'OPEN' AND f.risk_level IN ('HIGH', 'CRITICAL')
            ORDER BY f.risk_score DESC LIMIT 6
        """)
        top_findings = cursor.fetchall()
        
        f_table_data = [["Code", "Identity & Role", "Resource & Detail", "Risk Level", "Score"]]
        for f in top_findings:
            f_table_data.append([
                Paragraph(f["finding_code"], bold_body),
                Paragraph(f"{f['full_name']}<br/><font color='#64748b'>{f['role_name']}</font>", body_style),
                Paragraph(f"<b>{f['res_name']}</b><br/>{f['what_happened'][:70]}...", body_style),
                Paragraph(f"<font color='{'#b91c1c' if f['risk_level']=='CRITICAL' else '#c2410c'}'><b>{f['risk_level']}</b></font>", body_style),
                Paragraph(str(f["risk_score"]), bold_body)
            ])
        t_findings = Table(f_table_data, colWidths=[65, 120, 245, 65, 35])
        t_findings.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0f172a')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('BOTTOMPADDING', (0,0), (-1,0), 5),
            ('TOPPADDING', (0,0), (-1,0), 5),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#94a3b8')),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
            ('TOPPADDING', (0,1), (-1,-1), 4),
            ('BOTTOMPADDING', (0,1), (-1,-1), 4),
        ]))
        story.append(t_findings)
        story.append(Spacer(1, 14))

        # 3. Inactive Permissions (60-Day Dormancy Rule)
        story.append(Paragraph("3. Inactive Permissions (Requires Revalidation / Revocation)", h2_style))
        cursor.execute("""
            SELECT u.full_name, res.name as res_name, p.permission_type, p.start_date, p.last_used_at, p.reason
            FROM permissions p
            JOIN users u ON p.user_id = u.id
            JOIN resources res ON p.resource_id = res.id
            WHERE p.status = 'INACTIVE'
            LIMIT 5
        """)
        inactives = cursor.fetchall()
        inact_table = [["User", "Resource", "Permission", "Last Used", "Granted Reason"]]
        for inc in inactives:
            inact_table.append([
                Paragraph(inc["full_name"], body_style),
                Paragraph(inc["res_name"], body_style),
                Paragraph(inc["permission_type"], bold_body),
                Paragraph(inc["last_used_at"][:10] if inc["last_used_at"] else "Never", body_style),
                Paragraph(inc["reason"][:45] + "...", body_style)
            ])
        t_inact = Table(inact_table, colWidths=[100, 140, 60, 70, 160])
        t_inact.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#334155')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#94a3b8')),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ]))
        story.append(t_inact)
        story.append(Spacer(1, 14))

        # 4. Recommendations & Corrective Actions
        story.append(Paragraph("4. Recommended Governance Actions", h2_style))
        recs = [
            "1. <b>Revoke Intern High-Impact Privileges:</b> Immediately revoke EDIT privileges granted to non-permanent accounts on RESTRICTED human resources and payroll files.",
            "2. <b>Process Dormant Revalidations:</b> Conduct department review on permissions with 60+ days of recorded inactivity. Revoke access where projects have completed.",
            "3. <b>Enforce Baseline Scope:</b> Restrict engineering roles from holding persistent access to finance documents unless an active, time-bound project ticket is verified.",
            "4. <b>Mitigate Repeated Extensions:</b> Establish managerial escalation policy for any permission extended 3 or more times."
        ]
        for r in recs:
            story.append(Paragraph(r, body_style))
            story.append(Spacer(1, 4))

    doc.build(story)
    return output_path
