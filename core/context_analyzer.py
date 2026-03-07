from __future__ import annotations


class ContextAnalyzer:

    LOW_RISK_WORDS = {"test", "example", "dummy", "sample", "mock"}

    def analyze_context(self, line: str) -> dict[str, bool]:
        lowered = line.lower()
        is_comment = self._is_comment_line(line)
        has_low_risk_words = any(word in lowered for word in self.LOW_RISK_WORDS)

        return {
            "is_comment": is_comment,
            "has_low_risk_words": has_low_risk_words,
            "should_downgrade": is_comment or has_low_risk_words,
        }

    def adjust_risk(self, risk_level: str, line: str) -> str:
        
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
        stripped = line.strip()
        return stripped.startswith(("#", "//", "/*", "*", "--"))