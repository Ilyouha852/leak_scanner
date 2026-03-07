from __future__ import annotations

import subprocess
from typing import Iterable

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFontMetrics
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPlainTextEdit,
    QProgressBar,
    QScrollBar,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from models.leak_result import LeakResult

import os
from pathlib import Path


class ScanView(QWidget):

    ide_requested = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._leak_data: list[LeakResult] = []
        self._current_project_path: str = ""
        self._setup_ui()

    def _setup_ui(self) -> None:
        main_layout = QVBoxLayout(self)

        top_frame = QFrame()
        top_layout = QHBoxLayout(top_frame)

        self.files_label = QLabel("Файлов: 0")
        self.leaks_label = QLabel("Утечек: 0")

        ide_label = QLabel("Открыть в IDE:")
        self.ide_combo = QComboBox()
        self.ide_combo.addItems(["VS Code", "PyCharm", "WebStorm", "Sublime Text", "Нет"])
        self.ide_combo.setFixedWidth(120)
        self.ide_combo.setToolTip("Выберите IDE для открытия файла с утечкой")

        top_layout.addWidget(self.files_label)
        top_layout.addWidget(self.leaks_label)
        top_layout.addStretch(1)
        top_layout.addWidget(ide_label)
        top_layout.addWidget(self.ide_combo)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)

        self.results_table = QTableWidget(0, 6)
        self.results_table.setHorizontalHeaderLabels(
            ["Файл", "Строка", "Тип секрета", "Риск", "Детектор", "Фрагмент"]
        )

        header = self.results_table.horizontalHeader()
        header.setStretchLastSection(False)
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)

        self.results_table.setColumnWidth(0, 200)
        self.results_table.setColumnWidth(1, 50)
        self.results_table.setColumnWidth(2, 120)
        self.results_table.setColumnWidth(3, 60)
        self.results_table.setColumnWidth(4, 80)
        self.results_table.setColumnWidth(5, 200)

        for col in range(6):
            item = self.results_table.horizontalHeaderItem(col)
            if item:
                item.setToolTip(f"Столбец: {item.text()}")

        self.results_table.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.results_table.setSizeAdjustPolicy(QTableWidget.SizeAdjustPolicy.AdjustToContentsOnFirstShow)

        self.results_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.results_table.setAlternatingRowColors(True)

        self.results_table.cellDoubleClicked.connect(self._on_row_double_clicked)

        self.log_output = QPlainTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setPlaceholderText("Логи сканирования...")

        main_layout.addWidget(top_frame)
        main_layout.addWidget(self.progress_bar)
        main_layout.addWidget(self.results_table, stretch=3)
        main_layout.addWidget(QLabel("Логи"))
        main_layout.addWidget(self.log_output, stretch=1)

    def set_progress(self, percent: int) -> None:
        self.progress_bar.setValue(max(0, min(100, percent)))

    def set_statistics(self, scanned_files: int, leaks_count: int) -> None:
        self.files_label.setText(f"Файлов: {scanned_files}")
        self.leaks_label.setText(f"Утечек: {leaks_count}")

    def append_log(self, message: str) -> None:
        self.log_output.appendPlainText(message)

    def clear(self) -> None:
        self.results_table.setRowCount(0)
        self.log_output.clear()
        self.set_progress(0)
        self.set_statistics(scanned_files=0, leaks_count=0)

    def display_results(self, results: Iterable[LeakResult], project_path: str = "") -> None:
        self._leak_data = list(results)
        self._current_project_path = project_path
        self.results_table.setRowCount(len(self._leak_data))

        max_file_path_width = 0
        font_metrics = QFontMetrics(self.results_table.font())

        for row_idx, leak in enumerate(self._leak_data):
            values = [
                leak.file_path,
                str(leak.line_number),
                leak.secret_type,
                leak.risk_level,
                leak.detector_type,
                leak.code_fragment,
            ]

            file_path_width = font_metrics.horizontalAdvance(leak.file_path) + 20
            max_file_path_width = max(max_file_path_width, file_path_width)

            for col_idx, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setFlags(item.flags() ^ Qt.ItemFlag.ItemIsEditable)
                self.results_table.setItem(row_idx, col_idx, item)

        optimal_width = max(150, min(max_file_path_width, 500))
        self.results_table.setColumnWidth(0, optimal_width)

        self.results_table.setColumnWidth(1, 50)
        self.results_table.setColumnWidth(2, 130)
        self.results_table.setColumnWidth(3, 60)
        self.results_table.setColumnWidth(4, 90)
        self.results_table.setColumnWidth(5, 250)

    def set_project_path(self, path: str) -> None:
        self._current_project_path = path

    def _on_row_double_clicked(self, row: int, column: int) -> None:
        selected_ide = self.ide_combo.currentText()

        if selected_ide == "Нет" or not self._leak_data:
            return

        if row >= len(self._leak_data):
            return

        leak = self._leak_data[row]
        self._open_in_ide(leak.file_path, leak.line_number, selected_ide)

    def _open_in_ide(self, file_path: str, line_number: int, ide_name: str) -> None:

        if Path(file_path).is_absolute():
            abs_path = Path(file_path)
        elif self._current_project_path:
            abs_path = Path(self._current_project_path) / file_path
        else:
            abs_path = Path(file_path)

        if not abs_path.exists():
            self.append_log(f"Файл не найден: {abs_path}")
            return

        normalized_path = str(abs_path).replace("\\", "/")

        try:
            if ide_name == "VS Code":
                url = f"vscode://file/{normalized_path}:{line_number}"
                self._open_url(url)

            elif ide_name == "PyCharm":
                url = f"pycharm://open?file={normalized_path}&line={line_number}"
                self._open_url(url)

            elif ide_name == "WebStorm":
                url = f"webstorm://open?file={normalized_path}&line={line_number}"
                self._open_url(url)

            elif ide_name == "Sublime Text":
                import urllib.parse
                encoded_path = urllib.parse.quote(normalized_path)
                url = f"subl://open?url=file://{encoded_path}&line:{line_number}"
                self._open_url(url)

            self.append_log(f"Открыто в {ide_name}: {abs_path}:{line_number}")

        except Exception as e:
            self.append_log(f"Ошибка открытия в {ide_name}: {e}")

    def _open_url(self, url: str) -> None:
        from PySide6.QtGui import QDesktopServices
        from PySide6.QtCore import QUrl

        QDesktopServices.openUrl(QUrl(url))
