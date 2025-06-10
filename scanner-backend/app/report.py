from typing import List, Optional
import pdfkit
from jinja2 import Environment, FileSystemLoader
from datetime import datetime
from pathlib import Path
from sqlalchemy.orm import Session
from .models import Scan, Detection

class ReportGenerator:
    def __init__(self, template_dir: str = "app/templates"):
        self.env = Environment(loader=FileSystemLoader(template_dir))
        self.template = self.env.get_template("report.html")
        
        # Configure pdfkit options
        self.options = {
            'page-size': 'A4',
            'margin-top': '20mm',
            'margin-right': '20mm',
            'margin-bottom': '20mm',
            'margin-left': '20mm',
            'encoding': 'UTF-8',
            'no-outline': None
        }

    async def generate_pdf(
        self,
        scan: Scan,
        findings: List[Detection],
        db: Session
    ) -> bytes:
        """Generate PDF report from scan findings."""
        # Render template with data
        html = self.template.render(
            scan=scan,
            findings=findings,
            generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        )

        # Convert HTML to PDF
        try:
            pdf = pdfkit.from_string(html, False, options=self.options)
            return pdf
        except Exception as e:
            raise Exception(f"Failed to generate PDF: {str(e)}")

async def get_scan_report(scan_id: str, db: Session) -> Optional[bytes]:
    """Get scan report as PDF bytes."""
    # Query scan and findings
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        return None

    findings = (
        db.query(Detection)
        .filter(Detection.scan_id == scan_id)
        .order_by(Detection.severity.desc(), Detection.created_at.desc())
        .all()
    )

    # Generate PDF
    generator = ReportGenerator()
    return await generator.generate_pdf(scan, findings, db) 