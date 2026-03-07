"""Главное окно приложения Leak Scanner."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from core.project_detector import ProjectDetector
from core.scanner import Scanner
from llm.ollama_client import OllamaClient
from report.json_exporter import JSONExporter
from report.pdf_exporter import PDFExporter
from report.report_builder import ReportBuilder
from report.yaml_exporter import YAMLExporter
from ui.scan_view import ScanView


class MainWindow(QMainWindow):
    """Главное окно с управлением сканированием и экспортом отчётов."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Leak Scanner")
        self.resize(1800, 800)

        self.selected_folder: Path | None = None
        self.last_scan_results = []
        self.last_scanned_files = 0

        self.project_detector = ProjectDetector()
        self.scanner = Scanner()
        self.report_builder = ReportBuilder(ollama_client=OllamaClient())

        self._setup_ui()

    def _setup_ui(self) -> None:
        central = QWidget(self)
        self.setCentralWidget(central)

        layout = QVBoxLayout(central)
        top_row = QHBoxLayout()

        self.folder_input = QLineEdit()
        self.folder_input.setPlaceholderText("Выберите папку проекта...")
        self.folder_input.setReadOnly(True)

        self.select_button = QPushButton("Выбрать папку")
        self.scan_button = QPushButton("Сканировать")
        self.report_button = QPushButton("Создать отчет")
        self.format_combo = QComboBox()
        self.format_combo.addItems(["PDF", "JSON", "YAML"])
        self.format_combo.setFixedWidth(100)

        self.select_button.clicked.connect(self.select_folder)
        self.scan_button.clicked.connect(self.start_scan)
        self.report_button.clicked.connect(self.create_report)

        top_row.addWidget(self.folder_input)
        top_row.addWidget(self.select_button)
        top_row.addWidget(self.scan_button)
        top_row.addWidget(self.report_button)
        top_row.addWidget(self.format_combo)

        self.scan_view = ScanView(self)

        layout.addLayout(top_row)
        layout.addWidget(self.scan_view)

    def select_folder(self) -> None:
        """Открывает диалог выбора директории проекта."""
        selected = QFileDialog.getExistingDirectory(self, "Выберите папку проекта")
        if not selected:
            return

        self.selected_folder = Path(selected)
        self.folder_input.setText(str(self.selected_folder))
        self.scan_view.append_log(f"Выбрана папка: {self.selected_folder}")

    def start_scan(self) -> None:
        """Запускает проверку и сканирование выбранной папки."""
        if self.selected_folder is None:
            QMessageBox.warning(self, "Leak Scanner", "Сначала выберите папку проекта.")
            return

        if not self.project_detector.is_project(self.selected_folder):
            answer = QMessageBox.question(
                self,
                "Leak Scanner",
                "Папка не похожа на программный проект. Продолжить сканирование?",
            )
            if answer != QMessageBox.StandardButton.Yes:
                return

        self.scan_view.clear()
        self.scan_view.append_log("Старт сканирования...")

        self.scan_button.setEnabled(False)
        self.report_button.setEnabled(False)

        try:
            leaks, scanned_files = self.scanner.scan_project(
                self.selected_folder,
                progress_callback=self._on_scan_progress,
            )
            self.last_scan_results = leaks
            self.last_scanned_files = scanned_files

            self.scan_view.display_results(leaks)
            self.scan_view.set_statistics(scanned_files=scanned_files, leaks_count=len(leaks))
            self.scan_view.append_log(
                f"Сканирование завершено. Найдено {len(leaks)} потенциальных утечек."
            )
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Ошибка сканирования", str(exc))
            self.scan_view.append_log(f"Ошибка: {exc}")
        finally:
            self.scan_button.setEnabled(True)
            self.report_button.setEnabled(True)
            self.scan_view.set_progress(100)

    def _on_scan_progress(self, current: int, total: int, file_path: str) -> None:
        """Колбэк прогресса сканирования."""
        percent = int((current / total) * 100) if total else 100
        self.scan_view.set_progress(percent)
        self.scan_view.append_log(f"[{current}/{total}] {file_path}")

    def create_report(self) -> None:
        """Создает и экспортирует отчет в выбранном формате."""
        if self.selected_folder is None or not self.last_scan_results:
            QMessageBox.information(
                self,
                "Leak Scanner",
                "Нет результатов сканирования для формирования отчета.",
            )
            return

        report_data = self.report_builder.build_report(
            project_path=self.selected_folder,
            leaks=self.last_scan_results,
            scanned_files=self.last_scanned_files,
        )

        selected_format = self.format_combo.currentText()
        extension = ".pdf" if selected_format == "PDF" else f".{selected_format.lower()}"

        export_path_str, _ = QFileDialog.getSaveFileName(
            self,
            "Сохранить отчет",
            f"leak_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}{extension}",
            f"{selected_format} (*{extension})",
        )
        if not export_path_str:
            return

        export_path = Path(export_path_str)
        if export_path.suffix.lower() != extension:
            export_path = export_path.with_suffix(extension)

        try:
            if selected_format == "PDF":
                PDFExporter().export(report_data, export_path)
            elif selected_format == "JSON":
                JSONExporter().export(report_data, export_path)
            else:
                YAMLExporter().export(report_data, export_path)

            self.scan_view.append_log(f"Отчет сохранен: {export_path}")
            QMessageBox.information(self, "Leak Scanner", f"Отчет сохранен:\n{export_path}")

        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Ошибка экспорта", str(exc))
            self.scan_view.append_log(f"Ошибка экспорта: {exc}")