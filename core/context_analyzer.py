"""Контекстный анализ для понижения ложных срабатываний."""

from __future__ import annotations


class ContextAnalyzer:
    """Анализирует строку и корректирует риск находки."""

    LOW_RISK_WORDS = {"test", "example", "dummy", "sample", "mock"}

    def analyze_context(self, line: str) -> dict[str, bool]:
        """Возвращает признаки контекста для строки."""
        lowered = line.lower()
        is_comment = self._is_comment_line(line)
        has_low_risk_words = any(word in lowered for word in self.LOW_RISK_WORDS)

        return {
            "is_comment": is_comment,
            "has_low_risk_words": has_low_risk_words,
            "should_downgrade": is_comment or has_low_risk_words,
        }

    def adjust_risk(self, risk_level: str, line: str) -> str:
        """Понижает уровень риска при тестовом/комментарном контексте."""
        
        context = self.analyze_context(line)
        
        if not context["should_downgrade"]:
            return risk_level

        if risk_level == "high":
            return "high"
        
        if risk_level == "medium":
            return "medium"
        
        return "low"

    @staticmethod
    def _is_comment_line(line: str) -> bool:
        """Проверяет, является ли строка комментарием."""
        stripped = line.strip()
        return stripped.startswith(("#", "//", "/*", "*", "--"))