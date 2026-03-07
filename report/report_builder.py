from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from llm.ollama_client import OllamaClient
from models.leak_result import LeakResult


class ReportBuilder:

    def __init__(self, ollama_client: OllamaClient | None = None) -> None:
        self.ollama_client = ollama_client or OllamaClient()

    def build_report(
        self,
        project_path: Path,
        leaks: Iterable[LeakResult],
        scanned_files: int,
    ) -> dict:

        leak_list = list(leaks)

        risk_stats = {
            "high": sum(1 for item in leak_list if item.risk_level == "high"),
            "medium": sum(1 for item in leak_list if item.risk_level == "medium"),
            "low": sum(1 for item in leak_list if item.risk_level == "low"),
        }

        return {
            "project": {
                "path": str(project_path),
                "name": project_path.name,
            },
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "statistics": {
                "scanned_files": scanned_files,
                "total_leaks": len(leak_list),
                "risk": risk_stats,
            },
            "leaks": [item.to_dict() for item in leak_list],
            "llm_recommendations": self.ollama_client.generate_recommendations(leak_list),
        }