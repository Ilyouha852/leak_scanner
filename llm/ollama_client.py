"""Клиент для локального Ollama API."""

from __future__ import annotations

from typing import Iterable

import requests

from models.leak_result import LeakResult


class OllamaClient:
    """Обертка для генерации рекомендаций через локальную LLM Ollama."""

    API_URL = "http://localhost:11434/api/generate"
    MODEL = "qwen2.5:instruct"

    def generate_recommendations(self, leaks: Iterable[LeakResult]) -> str:
        """Генерирует рекомендации по списку найденных утечек."""
        leaks_list = list(leaks)
        if not leaks_list:
            return "Утечки не обнаружены. Рекомендации не требуются."

        prompt_lines = [
            "Ты security-ассистент. Дай короткие практические рекомендации по устранению утечек.",
            "Формат: список шагов на русском.",
            "Найденные утечки:",
        ]
        for leak in leaks_list[:50]:
            prompt_lines.append(
                f"- {leak.secret_type} | {leak.risk_level} | {leak.file_path}:{leak.line_number}"
            )

        payload = {
            "model": self.MODEL,
            "prompt": "\n".join(prompt_lines),
            "stream": False,
        }

        try:
            response = requests.post(self.API_URL, json=payload, timeout=30)
            response.raise_for_status()
            data = response.json()
            return str(data.get("response", "Не удалось получить ответ от модели.")).strip()
        except requests.RequestException as exc:
            return (
                "Не удалось получить рекомендации от Ollama. "
                f"Проверьте запуск сервера на {self.API_URL}. Ошибка: {exc}"
            )