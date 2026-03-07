"""Экспорт отчета в PDF-формат."""

from __future__ import annotations

from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


class PDFExporter:
    """Создает PDF-отчет на основе структуры report_data."""

    def export(self, report_data: dict, output_path: Path) -> None:
        """Сохраняет PDF файл отчета."""
        output_path.parent.mkdir(parents=True, exist_ok=True)

        doc = SimpleDocTemplate(str(output_path), pagesize=A4)
        styles = getSampleStyleSheet()
        story = []

        story.append(Paragraph("Leak Scanner Report", styles["Title"]))
        story.append(Spacer(1, 6 * mm))

        project = report_data.get("project", {})
        stats = report_data.get("statistics", {})
        risk = stats.get("risk", {})

        story.append(Paragraph(f"Project: {project.get('name', '')}", styles["Normal"]))
        story.append(Paragraph(f"Path: {project.get('path', '')}", styles["Normal"]))
        story.append(Paragraph(f"Generated at: {report_data.get('generated_at', '')}", styles["Normal"]))
        story.append(Spacer(1, 4 * mm))

        story.append(Paragraph("Statistics", styles["Heading2"]))
        story.append(Paragraph(f"Scanned files: {stats.get('scanned_files', 0)}", styles["Normal"]))
        story.append(Paragraph(f"Total leaks: {stats.get('total_leaks', 0)}", styles["Normal"]))
        story.append(
            Paragraph(
                (
                    "Risk levels — "
                    f"high: {risk.get('high', 0)}, "
                    f"medium: {risk.get('medium', 0)}, "
                    f"low: {risk.get('low', 0)}"
                ),
                styles["Normal"],
            )
        )
        story.append(Spacer(1, 6 * mm))

        story.append(Paragraph("Detected leaks", styles["Heading2"]))
        table_data = [["File", "Line", "Type", "Risk", "Detector", "Fragment"]]
        for leak in report_data.get("leaks", [])[:200]:
            table_data.append(
                [
                    str(leak.get("file_path", ""))[-45:],
                    str(leak.get("line_number", "")),
                    str(leak.get("secret_type", "")),
                    str(leak.get("risk_level", "")),
                    str(leak.get("detector_type", "")),
                    str(leak.get("code_fragment", ""))[:60],
                ]
            )

        table = Table(table_data, repeatRows=1)
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.black),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        story.append(table)
        story.append(Spacer(1, 6 * mm))

        story.append(Paragraph("LLM recommendations", styles["Heading2"]))
        rec_text = str(report_data.get("llm_recommendations", ""))
        story.append(Paragraph(rec_text.replace("\n", "<br/>"), styles["Normal"]))

        doc.build(story)