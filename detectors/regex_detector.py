"""Regex-детектор известных типов секретов."""

from __future__ import annotations

import re

from config.patterns import SECRET_PATTERNS
from models.leak_result import LeakResult


class RegexDetector:
    """Проверяет строку по набору регулярных выражений."""

    # Пример безопасной подстановки: ${MINIO_SECRET_KEY}
    ENV_REFERENCE_RE = re.compile(r"^\$[A-Za-z_][A-Za-z0-9_]*$")

    def detect(self, line: str, file_path: str, line_number: int) -> list[LeakResult]:
        """Возвращает список найденных утечек в строке."""
        results: list[LeakResult] = []

        for secret_name, rule in SECRET_PATTERNS.items():
            regex = rule["regex"]
            risk = str(rule["risk"])

            for match in regex.finditer(line):
                leak = self._build_leak_result(
                    secret_name=secret_name,
                    risk=risk,
                    match=match,
                    file_path=file_path,
                    line_number=line_number,
                )
                if leak is not None:
                    results.append(leak)

        return results

    def _build_leak_result(
        self,
        secret_name: str,
        risk: str,
        match: re.Match[str],
        file_path: str,
        line_number: int,
    ) -> LeakResult | None:
        """Строит LeakResult и отфильтровывает безопасные случаи."""
        full_fragment = match.group(0).strip()
        if not full_fragment:
            return None

        # Для assignment-паттернов сохраняем левую часть (имя переменной)
        # и правую часть (значение), чтобы результат был корректным.
        if match.lastindex and match.lastindex >= 2:
            variable_name = (match.group(1) or "").strip()
            value = (match.group(2) or "").strip()
            if not variable_name or not value:
                return None

            # Ссылка на env-переменную — не прямая утечка.
            if self.ENV_REFERENCE_RE.fullmatch(value):
                return None

            normalized_fragment = f"{variable_name}={value}"
        else:
            normalized_fragment = full_fragment

        return LeakResult(
            file_path=file_path,
            line_number=line_number,
            code_fragment=normalized_fragment[:200],
            secret_type=secret_name,
            risk_level=risk,
            detector_type="regex",
        )