"""Клиент для локального Ollama API."""

from __future__ import annotations

from typing import Iterable

import requests

from models.leak_result import LeakResult


class OllamaClient:
    """Обертка для генерации рекомендаций через локальную LLM Ollama."""

    API_URL = "http://localhost:11434/api/generate"
    MODEL = "llama3.2"

    def generate_recommendations(self, leaks: Iterable[LeakResult]) -> str:
        """Генерирует рекомендации по списку найденных утечек."""
        leaks_list = list(leaks)
        if not leaks_list:
            return "Утечки не обнаружены. Рекомендации не требуются."

        prompt_lines = [
            "Ты ассистент по безопасности программного обеспечения.",
            "Твоя задача — анализировать возможные утечки секретов в исходном коде.",
            "",
            "Важные правила:",
            "1. Анализируй КАЖДУЮ утечку отдельно.",
            "2. Для каждой утечки укажи:",
            "   - краткое описание проблемы",
            "   - уровень риска",
            "   - практическое решение",
            "3. Не объясняй теорию.",
            "4. Ответы должны быть краткими и практичными.",
            "5. Отвечай на русском языке.",
            "6. Только деловая информация. Без вступлений, без похвал.",
            "7. Не используй маркдаун, только текст.",
            "",
            "Формат вывода (строго соблюдай этот стиль):",
            "",
            "Утечка:",
            "Тип: <тип секрета>",
            "Местоположение: <имя_файла:строка>",
            "Риск: <краткое описание риска одной фразой>",
            "Исправление: <действия по шагам в формате '1) ... 2) ...'>",
            "",
            "Пример правильного ответа:",
            "",
            "Утечка:",
            "Тип: Секреты по логинам и паролям",
            "Местоположение: docker-compose-local.yml:12",
            "Риск: Известные секреты доступны для чтения",
            "Исправление: 1) Удалите секретные данные из docker-compose-local.yml. 2) Добавьте шифрование для секретных данных.",
            "",
            "ВАЖНО:",
            "- НЕ добавляй утечки, которых нет в списке",
            "- НЕ выдумывай утечки на соседних строках",
            "- Используй ТОЧНО такой же формат как в примере",
            "- После 'Исправление:' используй цифры с скобками: 1) ... 2) ...",
            "",
            "Теперь проанализируй следующие утечки:",
            "",
        ]

        for leak in leaks_list[:50]:
            prompt_lines.append(
                f"- {leak.secret_type} | {leak.risk_level} | {leak.file_path}:{leak.line_number} | Фрагмент: {leak.code_fragment}"
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