"""Модель результата обнаруженной утечки."""

from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(slots=True)
class LeakResult:
    """Описывает одно срабатывание детектора."""

    file_path: str
    line_number: int
    code_fragment: str
    secret_type: str
    risk_level: str
    detector_type: str

    def to_dict(self) -> dict:
        """Преобразует объект в словарь для сериализации."""
        return asdict(self)