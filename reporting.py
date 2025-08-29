# reporting.py
import json
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak
from reportlab.lib.units import inch

def build_pdf_report(target_domain: str, results: dict, out_path: str):
    """Generates a professional PDF report from scan results."""
    doc = SimpleDocTemplate(out_path, pagesize=A4,
                            rightMargin=inch/2, leftMargin=inch/2,
                            topMargin=inch/2, bottomMargin=inch/2)
    styles = getSampleStyleSheet()
    story = []

    # Title Page
    story.append(Paragraph("Automated Reconnaissance Report", styles['Title']))
    story.append(Spacer(1, 0.2 * inch))
    story.append(Paragraph(f"Target: {target_domain}", styles['h2']))
    story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
    story.append(PageBreak())

    # Results Sections
    for title, data in results.items():
        story.append(Paragraph(title, styles['h1']))
        story.append(Spacer(1, 0.1 * inch))

        if isinstance(data, dict):
            # Pretty print dictionary with proper formatting for PDF
            text = json.dumps(data, indent=4, ensure_ascii=False)
            text = text.replace('\n', '<br/>').replace(' ', '&nbsp;')
            story.append(Paragraph(f"<pre>{text}</pre>", styles['Code']))
        else:
            story.append(Paragraph(str(data), styles['Normal']))

        story.append(Spacer(1, 0.2 * inch))

    doc.build(story)