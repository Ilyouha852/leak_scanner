"""Главный модуль сканирования проекта."""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from core.context_analyzer import ContextAnalyzer
from core.file_collector import FileCollector
from detectors.entropy_detector import EntropyDetector
from detectors.regex_detector import RegexDetector
from models.leak_result import LeakResult


class Scanner:
    """Оркестратор сканирования файлов с запуском всех детекторов."""

    def __init__(self) -> None:
        self.file_collector = FileCollector()
        self.regex_detector = RegexDetector()
        self.entropy_detector = EntropyDetector()
        self.context_analyzer = ContextAnalyzer()

    def scan_project(
        self,
        project_path: Path,
        progress_callback: Callable[[int, int, str], None] | None = None,
    ) -> tuple[list[LeakResult], int]:
        """Сканирует проект и возвращает (утечки, число просканированных файлов)."""
        files = self.file_collector.collect_files(project_path)
        total = len(files)
        results: list[LeakResult] = []

        for index, file_path in enumerate(files, start=1):
            results.extend(self.scan_file(file_path))
            if progress_callback:
                progress_callback(index, total, str(file_path))

        return self._deduplicate(results), total

    def scan_file(self, file_path: Path) -> list[LeakResult]:
        """Сканирует файл построчно и применяет детекторы."""
        findings: list[LeakResult] = []

        try:
            with file_path.open("r", encoding="utf-8", errors="ignore") as file:
                for line_number, line in enumerate(file, start=1):
                    line_clean = line.rstrip("\n")

                    regex_hits = self.regex_detector.detect(
                        line=line_clean,
                        file_path=str(file_path),
                        line_number=line_number,
                    )
                    entropy_hits = self.entropy_detector.detect(
                        line=line_clean,
                        file_path=str(file_path),
                        line_number=line_number,
                    )
                    entropy_hits = self._drop_entropy_overlaps(regex_hits, entropy_hits)

                    for hit in [*regex_hits, *entropy_hits]:
                        hit.risk_level = self.context_analyzer.adjust_risk(
                            hit.risk_level,
                            line_clean,
                        )
                        findings.append(hit)
        except OSError:
            return findings

        return findings

    @staticmethod
    def _drop_entropy_overlaps(
        regex_hits: list[LeakResult],
        entropy_hits: list[LeakResult],
    ) -> list[LeakResult]:
        """Удаляет entropy-находки, которые дублируют или пересекают regex-находки."""
        if not regex_hits:
            return entropy_hits

        regex_fragments = [item.code_fragment for item in regex_hits]
        filtered: list[LeakResult] = []

        for entropy_item in entropy_hits:
            overlaps = any(
                entropy_item.code_fragment in regex_fragment
                or regex_fragment in entropy_item.code_fragment
                for regex_fragment in regex_fragments
            )
            if not overlaps:
                filtered.append(entropy_item)

        return filtered

    @staticmethod
    def _deduplicate(results: list[LeakResult]) -> list[LeakResult]:
        """Удаляет дубликаты результатов между детекторами."""
        seen: set[tuple[str, int, str, str]] = set()
        unique: list[LeakResult] = []

        for item in results:
            key = (item.file_path, item.line_number, item.code_fragment, item.secret_type)
            if key in seen:
                continue
            seen.add(key)
            unique.append(item)

        return unique