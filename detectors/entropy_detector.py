"""Эвристический детектор по энтропии."""

from __future__ import annotations

import re

from core.entropy import EntropyCalculator
from models.leak_result import LeakResult


class EntropyDetector:
    """Ищет высокоэнтропийные длинные токены в строках."""

    MIN_LENGTH = 20
    MIN_ENTROPY = 4.5
    TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_\-+/=]{20,}")

    def __init__(self) -> None:
        self.entropy_calculator = EntropyCalculator()

    def detect(self, line: str, file_path: str, line_number: int) -> list[LeakResult]:
        """Проверяет строку и возвращает подозрительные токены."""
        findings: list[LeakResult] = []

        for match in self.TOKEN_PATTERN.finditer(line):
            token = match.group(0)
            if len(token) <= self.MIN_LENGTH:
                continue

            entropy = self.entropy_calculator.calculate_entropy(token)
            if entropy <= self.MIN_ENTROPY:
                continue

            findings.append(
                LeakResult(
                    file_path=file_path,
                    line_number=line_number,
                    code_fragment=token[:200],
                    secret_type="High entropy string",
                    risk_level="medium",
                    detector_type="entropy",
                )
            )

        return findings