from __future__ import annotations

import json
from pathlib import Path


class JSONExporter:

    def export(self, report_data: dict, output_path: Path) -> None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with output_path.open("w", encoding="utf-8") as file:
            json.dump(report_data, file, ensure_ascii=False, indent=2)
