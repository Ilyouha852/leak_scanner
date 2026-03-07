"""Regex-детектор известных типов секретов."""

from __future__ import annotations

from config.patterns import SECRET_PATTERNS
from models.leak_result import LeakResult


class RegexDetector:
    """Проверяет строку по набору регулярных выражений."""

    def detect(self, line: str, file_path: str, line_number: int) -> list[LeakResult]:
        """Возвращает список найденных утечек в строке."""
        results: list[LeakResult] = []

        for secret_name, rule in SECRET_PATTERNS.items():
            regex = rule["regex"]
            risk = rule["risk"]
            for match in regex.finditer(line):
                fragment = match.group(0).strip()
                if not fragment:
                    continue
                results.append(
                    LeakResult(
                        file_path=file_path,
                        line_number=line_number,
                        code_fragment=fragment[:200],
                        secret_type=secret_name,
                        risk_level=str(risk),
                        detector_type="regex",
                    )
                )

        return results