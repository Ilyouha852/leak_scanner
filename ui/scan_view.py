"""Виджет отображения результатов, статистики и прогресса сканирования."""

from __future__ import annotations

from typing import Iterable

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QProgressBar,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from models.leak_result import LeakResult


class ScanView(QWidget):
    """Компонент UI для вывода результатов сканирования."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self) -> None:
        main_layout = QVBoxLayout(self)

        stats_frame = QFrame()
        stats_layout = QHBoxLayout(stats_frame)
        self.files_label = QLabel("Файлов: 0")
        self.leaks_label = QLabel("Утечек: 0")
        stats_layout.addWidget(self.files_label)
        stats_layout.addWidget(self.leaks_label)
        stats_layout.addStretch(1)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)

        self.results_table = QTableWidget(0, 6)
        self.results_table.setHorizontalHeaderLabels(
            ["Файл", "Строка", "Тип секрета", "Риск", "Детектор", "Фрагмент"]
        )
        self.results_table.horizontalHeader().setStretchLastSection(True)

        self.log_output = QPlainTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setPlaceholderText("Логи сканирования...")

        main_layout.addWidget(stats_frame)
        main_layout.addWidget(self.progress_bar)
        main_layout.addWidget(self.results_table, stretch=3)
        main_layout.addWidget(QLabel("Логи"))
        main_layout.addWidget(self.log_output, stretch=1)

    def set_progress(self, percent: int) -> None:
        """Обновляет прогресс-бар."""
        self.progress_bar.setValue(max(0, min(100, percent)))

    def set_statistics(self, scanned_files: int, leaks_count: int) -> None:
        """Обновляет статистику сканирования."""
        self.files_label.setText(f"Файлов: {scanned_files}")
        self.leaks_label.setText(f"Утечек: {leaks_count}")

    def append_log(self, message: str) -> None:
        """Добавляет строку в лог."""
        self.log_output.appendPlainText(message)

    def clear(self) -> None:
        """Очищает таблицу, прогресс и лог перед новым сканированием."""
        self.results_table.setRowCount(0)
        self.log_output.clear()
        self.set_progress(0)
        self.set_statistics(scanned_files=0, leaks_count=0)

    def display_results(self, results: Iterable[LeakResult]) -> None:
        """Заполняет таблицу результатами сканирования."""
        rows = list(results)
        self.results_table.setRowCount(len(rows))

        for row_idx, leak in enumerate(rows):
            values = [
                leak.file_path,
                str(leak.line_number),
                leak.secret_type,
                leak.risk_level,
                leak.detector_type,
                leak.code_fragment,
            ]
            for col_idx, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setFlags(item.flags() ^ Qt.ItemFlag.ItemIsEditable)
                self.results_table.setItem(row_idx, col_idx, item)