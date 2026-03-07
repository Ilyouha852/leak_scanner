"""Экспорт отчета в PDF-формат."""

from __future__ import annotations

from pathlib import Path

from reportlab import platypus
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT, TA_CENTER
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
import os

FONTS_DIR = "C:\\Windows\\Fonts"

pdfmetrics.registerFont(TTFont("Arial", os.path.join(FONTS_DIR, "arial.ttf")))
pdfmetrics.registerFont(TTFont("Arial-Bold", os.path.join(FONTS_DIR, "arialbd.ttf")))

DEFAULT_FONT = "Arial"
BOLD_FONT = "Arial-Bold"


class PDFExporter:
    """Создает PDF-отчет на основе структуры report_data."""

    def export(self, report_data: dict, output_path: Path) -> None:
        """Сохраняет PDF файл отчета."""
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Альбомная ориентация для вмещения широкой таблицы
        doc = SimpleDocTemplate(
            str(output_path),
            pagesize=landscape(A4),
            leftMargin=10 * mm,
            rightMargin=10 * mm,
            topMargin=15 * mm,
            bottomMargin=15 * mm,
        )

        # Кастомные стили с поддержкой кириллицы
        styles = {
            "title": ParagraphStyle(
                "Title",
                fontName=BOLD_FONT,
                fontSize=18,
                alignment=TA_CENTER,
                spaceAfter=6 * mm,
            ),
            "heading2": ParagraphStyle(
                "Heading2",
                fontName=BOLD_FONT,
                fontSize=14,
                spaceAfter=4 * mm,
                spaceBefore=4 * mm,
            ),
            "normal": ParagraphStyle(
                "Normal",
                fontName=DEFAULT_FONT,
                fontSize=9,
                alignment=TA_LEFT,
            ),
            "normal_bold": ParagraphStyle(
                "NormalBold",
                fontName=BOLD_FONT,
                fontSize=9,
            ),
        }

        story = []

        # Заголовок
        story.append(Paragraph("Leak Scanner Report", styles["title"]))

        # Информация о проекте
        project = report_data.get("project", {})
        stats = report_data.get("statistics", {})
        risk = stats.get("risk", {})

        story.append(Paragraph(f"Project: {project.get('name', '')}", styles["normal"]))
        story.append(Paragraph(f"Path: {project.get('path', '')}", styles["normal"]))
        story.append(Paragraph(f"Generated at: {report_data.get('generated_at', '')}", styles["normal"]))
        story.append(Spacer(1, 4 * mm))

        # Статистика
        story.append(Paragraph("Statistics", styles["heading2"]))
        story.append(
            Paragraph(
                f"Scanned files: {stats.get('scanned_files', 0)}",
                styles["normal"],
            )
        )
        story.append(
            Paragraph(
                f"Total leaks: {stats.get('total_leaks', 0)}",
                styles["normal"],
            )
        )
        story.append(
            Paragraph(
                (
                    "Risk levels — "
                    f"high: {risk.get('high', 0)}, "
                    f"medium: {risk.get('medium', 0)}, "
                    f"low: {risk.get('low', 0)}"
                ),
                styles["normal"],
            )
        )
        story.append(Spacer(1, 6 * mm))

        # Таблица утечек
        story.append(Paragraph("Detected leaks", styles["heading2"]))
        table_data = [
            [
                Paragraph("File", styles["normal_bold"]),
                Paragraph("Line", styles["normal_bold"]),
                Paragraph("Type", styles["normal_bold"]),
                Paragraph("Risk", styles["normal_bold"]),
                Paragraph("Detector", styles["normal_bold"]),
                Paragraph("Fragment", styles["normal_bold"]),
            ]
        ]

        for leak in report_data.get("leaks", [])[:150]:
            table_data.append(
                [
                    Paragraph(str(leak.get("file_path", ""))[-40:], styles["normal"]),
                    Paragraph(str(leak.get("line_number", "")), styles["normal"]),
                    Paragraph(str(leak.get("secret_type", "")), styles["normal"]),
                    Paragraph(str(leak.get("risk_level", "")), styles["normal"]),
                    Paragraph(str(leak.get("detector_type", "")), styles["normal"]),
                    Paragraph(str(leak.get("code_fragment", ""))[:50], styles["normal"]),
                ]
            )

        # Настройка таблицы с учётом ширины страницы в альбомной ориентации
        page_width = landscape(A4)[0] - 20 * mm
        col_widths = [
            page_width * 0.25,  # File
            page_width * 0.05,  # Line
            page_width * 0.15,  # Type
            page_width * 0.08,  # Risk
            page_width * 0.10,  # Detector
            page_width * 0.37,  # Fragment
        ]

        table = Table(table_data, repeatRows=1, colWidths=col_widths)
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.Color(0.2, 0.3, 0.5)),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                    ("FONTNAME", (0, 0), (-1, 0), BOLD_FONT),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("WORDWRAP", (0, 0), (-1, -1), "TRUE"),
                    ("BACKGROUND", (0, 1), (-1, -1), colors.white),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.Color(0.95, 0.95, 0.95)]),
                ]
            )
        )
        story.append(table)
        story.append(Spacer(1, 6 * mm))

        # Рекомендации LLM
        story.append(Paragraph("LLM recommendations", styles["heading2"]))
        rec_text = str(report_data.get("llm_recommendations", ""))
        if rec_text:
            # Разбиваем длинный текст на абзацы
            for para in rec_text.split("\n\n"):
                if para.strip():
                    story.append(Paragraph(para.replace("\n", "<br/>"), styles["normal"]))
                    story.append(Spacer(1, 3 * mm))
        else:
            story.append(Paragraph("No recommendations available.", styles["normal"]))

        doc.build(story)