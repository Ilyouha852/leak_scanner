"""Экспорт отчета в YAML."""

from __future__ import annotations

from pathlib import Path

import yaml


class YAMLExporter:
    """Сохраняет отчет в формате YAML."""

    def export(self, report_data: dict, output_path: Path) -> None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with output_path.open("w", encoding="utf-8") as file:
            yaml.safe_dump(report_data, file, allow_unicode=True, sort_keys=False)
