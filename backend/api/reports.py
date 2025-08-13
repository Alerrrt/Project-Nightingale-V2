from fastapi import APIRouter, HTTPException, Depends, Request
from fastapi.responses import FileResponse, StreamingResponse
from typing import Dict, Any, List, Tuple
import os
import io
import math
from pathlib import Path
from datetime import datetime
from backend.scanner_engine import ScannerEngine
from backend.utils.snapshot_store import load_snapshot
from backend.utils.newsletter_store import store_email

# Try to import reportlab for PDF generation
try:
    from reportlab.lib.pagesizes import letter, A4, landscape
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image, Drawing
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch, cm
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    from reportlab.graphics.shapes import Drawing, String, Circle, Rect, Line
    from reportlab.graphics.charts.barcharts import VerticalBarChart, HorizontalBarChart
    from reportlab.graphics.charts.legends import Legend
    from reportlab.graphics import renderPDF
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

router = APIRouter()

async def get_scanner_engine(request: Request) -> ScannerEngine:
    engine = getattr(request.app.state, "scanner_engine", None)
    if engine is None:
        raise Exception("Scanner engine not configured")
    return engine

@router.post("/scans/generate_pdf")
async def generate_pdf_report(
    payload: Dict[str, Any],
    engine: ScannerEngine = Depends(get_scanner_engine)
):
    """Generate and return a dynamic PDF report for a scan."""
    try:
        scan_id = payload.get("scan_id")
        url = payload.get("url")
        
        if not scan_id:
            raise HTTPException(status_code=400, detail="Scan ID is required")
        
        if not url:
            raise HTTPException(status_code=400, detail="URL is required")
        
        # Get scan results
        scan_data = None
        try:
            scan_data = await engine.get_scan_status(scan_id)
        except Exception:
            pass
        
        # Fallback to snapshot if live data not available
        if not scan_data:
            scan_data = load_snapshot(scan_id)
        
        if not scan_data:
            raise HTTPException(status_code=404, detail=f"Scan results not found for ID: {scan_id}")
        
        # Generate dynamic PDF if reportlab is available
        if REPORTLAB_AVAILABLE:
            pdf_buffer = generate_enhanced_dashboard_pdf(scan_data, url)
            return StreamingResponse(
                io.BytesIO(pdf_buffer.getvalue()),
                media_type="application/pdf",
                headers={"Content-Disposition": f"attachment; filename=nightingale_security_report_{scan_id}.pdf"}
            )
        else:
            # Fallback to static template
            pdf_path = Path("frontend/public/Pdf_Template.pdf")
            if not pdf_path.exists():
                raise HTTPException(status_code=404, detail="PDF template not found")
            
            return FileResponse(
                path=str(pdf_path),
                media_type="application/pdf",
                filename="nightingale_security_report.pdf"
            )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate PDF: {str(e)}")

@router.post("/scans/user_info")
async def save_user_info(payload: Dict[str, Any]):
    """Save user information when downloading reports."""
    try:
        email = payload.get("email")
        url = payload.get("url")
        
        if not email or "@" not in email:
            raise HTTPException(status_code=400, detail="Valid email is required")
        
        if not url:
            raise HTTPException(status_code=400, detail="URL is required")
        
        # Store the email (you can extend this to store more user info if needed)
        store_email(email)
        
        return {"status": "success", "message": "User information saved"}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save user info: {str(e)}")

# Returns a dynamic aggregated report, even if scan was cancelled (partial)
@router.get("/scans/{scan_id}/results", response_model=Dict)
async def get_scan_results(
    scan_id: str,
    engine: ScannerEngine = Depends(get_scanner_engine)
):
    """Get an aggregated report for a scan, including partial results if cancelled."""
    # Try live engine state first
    try:
        scan_data = await engine.get_scan_status(scan_id)
    except Exception:
        scan_data = None

    # Fallback to snapshot when live is missing or cancelled
    snapshot = load_snapshot(scan_id)

    if not scan_data and not snapshot:
        raise HTTPException(status_code=404, detail=f"Scan not found: {scan_id}")

    # Choose the freshest source
    report_source: Dict[str, Any] = {}
    if scan_data:
        report_source = scan_data
    elif snapshot:
        report_source = snapshot

    results = report_source.get("results", [])
    status = report_source.get("status", "unknown")
    start_time = report_source.get("start_time") or report_source.get("created_at")
    end_time = report_source.get("end_time") or report_source.get("completed_at")

    # Build a simple summary
    severity_counts: Dict[str, int] = {}
    for f in results:
        sev = (f.get("severity") or "info").lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    summary = {
        "total_findings": len(results),
        "by_severity": severity_counts,
        "scan_duration_seconds": None,
    }
    # Duration if timestamps available
    # Note: Frontend can interpret null if missing

    return {
        "scan_id": report_source.get("id") or scan_id,
        "target": report_source.get("target", ""),
        "scan_type": report_source.get("type") or report_source.get("scan_type"),
        "status": status,
        "results": {
            "findings": results,
            "summary": summary,
        },
        "created_at": start_time,
        "completed_at": end_time,
    }


@router.post("/newsletter/subscribe-and-unlock")
async def subscribe_and_unlock(payload: Dict[str, Any]):
    """Store email and return a token that the frontend can use to unlock report downloads."""
    email = (payload or {}).get("email")
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="Invalid email")
    try:
        store_email(email)
        # Minimal token; frontend just needs ack to show full report/downloads
        return {"status": "ok", "unlocked": True}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/newsletter/subscribe")
async def subscribe_newsletter(payload: Dict[str, Any]):
    email = (payload or {}).get("email")
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="Invalid email")
    try:
        store_email(email)
        return {"status": "ok"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def generate_enhanced_dashboard_pdf(scan_data: Dict[str, Any], target_url: str) -> io.BytesIO:
    """Generate an enhanced dashboard-style PDF report matching the screenshot layout."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=0.5*inch, bottomMargin=0.5*inch)
    story = []
    
    # Get styles
    styles = getSampleStyleSheet()
    
    # Custom styles matching the dark theme
    title_style = ParagraphStyle(
        'DashboardTitle',
        parent=styles['Heading1'],
        fontSize=28,
        spaceAfter=20,
        alignment=TA_LEFT,
        textColor=colors.white,
        fontName='Helvetica-Bold'
    )
    
    subtitle_style = ParagraphStyle(
        'DashboardSubtitle',
        parent=styles['Heading2'],
        fontSize=14,
        spaceAfter=10,
        alignment=TA_LEFT,
        textColor=colors.lightblue,
        fontName='Helvetica'
    )
    
    body_style = ParagraphStyle(
        'DashboardBody',
        parent=styles['Normal'],
        fontSize=12,
        spaceAfter=6,
        alignment=TA_LEFT,
        textColor=colors.white,
        fontName='Helvetica'
    )
    
    # Extract scan data
    findings = scan_data.get("results", [])
    scan_id = scan_data.get("id", "N/A")
    scan_status = scan_data.get("status", "N/A")
    start_time = scan_data.get("start_time")
    end_time = scan_data.get("end_time")
    
    # Calculate severity counts
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        severity = finding.get("severity", "info").lower()
        if severity in severity_counts:
            severity_counts[severity] += 1
    
    total_findings = sum(severity_counts.values())
    
    # Calculate overall severity percentage (based on weighted severity)
    if total_findings > 0:
        weighted_score = (
            severity_counts["critical"] * 100 +
            severity_counts["high"] * 75 +
            severity_counts["medium"] * 50 +
            severity_counts["low"] * 25 +
            severity_counts["info"] * 10
        ) / total_findings
        overall_severity = min(100, max(0, weighted_score))
    else:
        overall_severity = 0
    
    # Determine risk level
    if overall_severity >= 80:
        risk_level = "CRITICAL"
    elif overall_severity >= 60:
        risk_level = "HIGH"
    elif overall_severity >= 40:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"
    
    # Format timestamps
    report_date = datetime.now().strftime("%a, %d-%m-%Y, %H:%M")
    if start_time:
        try:
            start_dt = datetime.fromtimestamp(start_time) if isinstance(start_time, (int, float)) else start_time
            start_formatted = start_dt.strftime("%a, %d-%m-%Y, %H:%M")
        except:
            start_formatted = "N/A"
    else:
        start_formatted = "N/A"
    
    # Create dashboard layout
    # Header Section
    header_data = [
        ["LATEST SECURITY CHECK REPORT", "Unlock the Full Report Free by Creating an Account"],
        ["", "Get full report details and more testing capacity"]
    ]
    
    header_table = Table(header_data, colWidths=[4*inch, 3*inch])
    header_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, 0), colors.darkblue),
        ('BACKGROUND', (1, 0), (1, 1), colors.darkgrey),
        ('TEXTCOLOR', (0, 0), (0, 0), colors.white),
        ('TEXTCOLOR', (1, 0), (1, 1), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, 0), 'Helvetica-Bold'),
        ('FONTNAME', (1, 0), (1, 1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (0, 0), 16),
        ('FONTSIZE', (1, 0), (1, 1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ('TOPPADDING', (0, 0), (-1, -1), 10),
    ]))
    story.append(header_table)
    story.append(Spacer(1, 20))
    
    # Main content in 3 columns
    main_content_data = []
    
    # Left Column - Visual and Vulnerabilities Chart
    left_col = []
    
    # Placeholder for the person image (we'll create a simple representation)
    left_col.append(Paragraph("🔍 WEBSITE SECURITY SCAN", subtitle_style))
    left_col.append(Spacer(1, 10))
    
    # Vulnerabilities Identified Bar Chart
    left_col.append(Paragraph("Vulnerabilities Identified", subtitle_style))
    
    # Create horizontal bar chart
    chart_data = [
        severity_counts["critical"],
        severity_counts["high"], 
        severity_counts["medium"],
        severity_counts["low"]
    ]
    chart_labels = ["Critical", "High", "Medium", "Low"]
    chart_colors = [colors.darkred, colors.red, colors.orange, colors.yellow]
    
    # Create bar chart drawing
    chart_drawing = Drawing(4*inch, 2*inch)
    bar_chart = HorizontalBarChart()
    bar_chart.x = 1*inch
    bar_chart.y = 0.5*inch
    bar_chart.height = 1.2*inch
    bar_chart.width = 2.5*inch
    bar_chart.data = [chart_data]
    bar_chart.categoryAxis.categoryNames = chart_labels
    bar_chart.bars[0].fillColor = colors.purple
    bar_chart.bars[0].strokeColor = colors.purple
    bar_chart.valueAxis.valueMin = 0
    bar_chart.valueAxis.valueMax = max(chart_data) * 1.2 if chart_data else 100
    bar_chart.valueAxis.valueStep = max(chart_data) // 4 if chart_data else 25
    
    chart_drawing.add(bar_chart)
    left_col.append(chart_drawing)
    
    # Middle Column - Scan Details and Performance
    middle_col = []
    
    # Website URL
    middle_col.append(Paragraph(f"🌐 {target_url}", subtitle_style))
    middle_col.append(Spacer(1, 5))
    
    # Report metadata
    middle_col.append(Paragraph(f"Report Generated: {report_date}", body_style))
    middle_col.append(Paragraph("Server location: Chennai", body_style))
    middle_col.append(Paragraph("Location: Chennai", body_style))
    middle_col.append(Spacer(1, 10))
    
    # Severity breakdown
    severity_breakdown_data = [
        ["High", str(severity_counts["high"])],
        ["Medium", str(severity_counts["medium"])],
        ["Low", str(severity_counts["low"])],
        ["Information", str(severity_counts["info"])]
    ]
    
    severity_table = Table(severity_breakdown_data, colWidths=[1.5*inch, 0.5*inch])
    severity_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.darkgrey),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 1, colors.grey),
    ]))
    middle_col.append(severity_table)
    middle_col.append(Spacer(1, 10))
    
    # Overall Severity
    overall_severity_data = [["Overall Severity", f"{overall_severity:.0f}%"]]
    overall_table = Table(overall_severity_data, colWidths=[1.5*inch, 1*inch])
    overall_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.darkblue),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 12),
        ('GRID', (0, 0), (-1, -1), 1, colors.grey),
    ]))
    middle_col.append(overall_table)
    middle_col.append(Spacer(1, 10))
    
    # Performance breakdown (simplified donut charts)
    middle_col.append(Paragraph("Performance Breakdown", subtitle_style))
    
    # Create simple performance metrics
    performance_data = [
        ["Blog", "800", "2%"],
        ["Text", "1200", "3%"],
        ["Picture", "1600", "4%"],
        ["Video", "2000", "6%"]
    ]
    
    perf_table = Table(performance_data, colWidths=[1*inch, 0.8*inch, 0.5*inch])
    perf_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.darkgrey),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 1, colors.grey),
    ]))
    middle_col.append(perf_table)
    
    # Right Column - Risk Level and Pie Chart
    right_col = []
    
    # Risk Level
    risk_level_data = [["Risk Level", risk_level]]
    risk_table = Table(risk_level_data, colWidths=[1.5*inch, 1.5*inch])
    risk_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.darkred),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 14),
        ('GRID', (0, 0), (-1, -1), 1, colors.red),
    ]))
    right_col.append(risk_table)
    right_col.append(Spacer(1, 10))
    
    # Risk Levels Pie Chart
    right_col.append(Paragraph("Risk Levels", subtitle_style))
    
    # Create pie chart
    pie_data = []
    pie_labels = []
    pie_colors = []
    
    if severity_counts["critical"] > 0:
        pie_data.append(severity_counts["critical"])
        pie_labels.append("Critical")
        pie_colors.append(colors.darkred)
    
    if severity_counts["high"] > 0:
        pie_data.append(severity_counts["high"])
        pie_labels.append("High")
        pie_colors.append(colors.red)
    
    if severity_counts["medium"] > 0:
        pie_data.append(severity_counts["medium"])
        pie_labels.append("Medium")
        pie_colors.append(colors.orange)
    
    if severity_counts["low"] > 0:
        pie_data.append(severity_counts["low"])
        pie_labels.append("Low")
        pie_colors.append(colors.yellow)
    
    if not pie_data:
        pie_data = [1]
        pie_labels = ["No Issues"]
        pie_colors = [colors.green]
    
    # Create pie chart drawing
    pie_drawing = Drawing(2.5*inch, 2*inch)
    
    # Create a simple pie chart representation using circles and text
    center_x = 1.25*inch
    center_y = 1*inch
    radius = 0.8*inch
    
    if len(pie_data) > 0:
        total = sum(pie_data)
        
        # Create a main circle
        main_circle = Circle(center_x, center_y, radius)
        main_circle.fillColor = colors.darkgrey
        main_circle.strokeColor = colors.white
        main_circle.strokeWidth = 2
        pie_drawing.add(main_circle)
        
        # Add labels around the circle
        for i, (value, label, color) in enumerate(zip(pie_data, pie_labels, pie_colors)):
            if total > 0:
                percentage = (value / total) * 100
                angle = (i / len(pie_data)) * 360
                
                # Position label around the circle
                label_x = center_x + (radius * 0.8) * math.cos(math.radians(angle))
                label_y = center_y + (radius * 0.8) * math.sin(math.radians(angle))
                
                # Add colored circle indicator
                indicator_radius = 0.1*inch
                indicator = Circle(label_x, label_y, indicator_radius)
                indicator.fillColor = color
                indicator.strokeColor = colors.white
                indicator.strokeWidth = 1
                pie_drawing.add(indicator)
                
                # Add text label
                text_x = label_x + 0.2*inch
                text_y = label_y
                label_text = String(text_x, text_y, f"{label}: {value} ({percentage:.0f}%)")
                label_text.fontSize = 8
                label_text.fillColor = colors.white
                label_text.textAnchor = 'start'
                pie_drawing.add(label_text)
    right_col.append(pie_drawing)
    
    # Combine all columns
    main_content_data.append([left_col, middle_col, right_col])
    
    main_content_table = Table(main_content_data, colWidths=[2.5*inch, 2.5*inch, 2*inch])
    main_content_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.darkblue),
        ('ALIGN', (0, 0), (-1, -1), 'TOP'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
        ('TOPPADDING', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
    ]))
    
    story.append(main_content_table)
    story.append(Spacer(1, 20))
    
    # Additional scan details
    details_data = [
        ["Scan ID", scan_id],
        ["Scan Status", scan_status],
        ["Start Time", start_formatted],
        ["Total Findings", str(total_findings)],
        ["Critical Issues", str(severity_counts["critical"])],
        ["High Issues", str(severity_counts["high"])],
        ["Medium Issues", str(severity_counts["medium"])],
        ["Low Issues", str(severity_counts["low"])],
        ["Info Issues", str(severity_counts["info"])],
    ]
    
    details_table = Table(details_data, colWidths=[2*inch, 5*inch])
    details_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.darkgrey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.darkblue),
        ('GRID', (0, 0), (-1, -1), 1, colors.grey)
    ]))
    story.append(details_table)
    
    # Build PDF
    doc.build(story)
    buffer.seek(0)
    return buffer


def generate_dynamic_pdf(scan_data: Dict[str, Any], target_url: str) -> io.BytesIO:
    """Generate a dynamic PDF report with scan results."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4)
    story = []
    
    # Get styles
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        spaceAfter=30,
        alignment=TA_CENTER,
        textColor=colors.darkblue
    )
    
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=16,
        spaceAfter=12,
        textColor=colors.darkblue
    )
    
    # Title
    story.append(Paragraph("Nightingale Security Scan Report", title_style))
    story.append(Spacer(1, 20))
    
    # Scan Information
    story.append(Paragraph("Scan Information", heading_style))
    scan_info_data = [
        ["Target URL", target_url],
        ["Scan ID", scan_data.get("id", "N/A")],
        ["Scan Type", scan_data.get("type", "N/A")],
        ["Status", scan_data.get("status", "N/A")],
        ["Start Time", scan_data.get("start_time", "N/A")],
        ["End Time", scan_data.get("end_time", "N/A")],
    ]
    
    scan_info_table = Table(scan_info_data, colWidths=[2*inch, 4*inch])
    scan_info_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    story.append(scan_info_table)
    story.append(Spacer(1, 20))
    
    # Findings Summary
    findings = scan_data.get("results", [])
    if findings:
        story.append(Paragraph("Findings Summary", heading_style))
        
        # Count findings by severity
        severity_counts = {}
        for finding in findings:
            severity = finding.get("severity", "Info").lower()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        summary_data = [["Severity", "Count"]]
        for severity, count in severity_counts.items():
            summary_data.append([severity.title(), str(count)])
        
        summary_table = Table(summary_data, colWidths=[2*inch, 1*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 20))
        
        # Detailed Findings
        story.append(Paragraph("Detailed Findings", heading_style))
        
        for i, finding in enumerate(findings[:10], 1):  # Limit to first 10 findings
            story.append(Paragraph(f"Finding {i}: {finding.get('title', 'Untitled')}", styles['Heading3']))
            
            finding_data = [
                ["Severity", finding.get("severity", "Info")],
                ["Location", finding.get("location", "N/A")],
                ["Description", finding.get("description", "N/A")[:200] + "..." if len(finding.get("description", "")) > 200 else finding.get("description", "N/A")],
                ["CWE", finding.get("cwe", "N/A")],
                ["CVE", finding.get("cve", "N/A")],
            ]
            
            finding_table = Table(finding_data, colWidths=[1.5*inch, 4.5*inch])
            finding_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(finding_table)
            story.append(Spacer(1, 12))
            
            if i < len(findings[:10]):
                story.append(PageBreak())
    
    # Build PDF
    doc.build(story)
    buffer.seek(0)
    return buffer
