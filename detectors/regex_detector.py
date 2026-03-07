from __future__ import annotations

import re

from config.patterns import SECRET_PATTERNS
from models.leak_result import LeakResult


class RegexDetector:

    ENV_REFERENCE_PATTERNS = (
        re.compile(r"^\$[A-Za-z_][A-Za-z0-9_]*$"),
        re.compile(r"^\$\{[A-Za-z_][A-Za-z0-9_]*\}$"),
        re.compile(r"^(?:process\.env|import\.meta\.env)\.[A-Za-z_][A-Za-z0-9_]*$"),
        re.compile(r"^os\.getenv\(['\"][A-Za-z_][A-Za-z0-9_]*['\"]\)$"),
    )

    PLACEHOLDER_VALUE_RE = re.compile(
        r"(?i)^(?:"
        r"hashed[-_ ]?password|"
        r"test[-_ ]?(?:password|secret|token)?|"
        r"example|dummy|sample|mock|"
        r"changeme|replace[-_ ]?me|your[-_ ]?(?:password|secret|token)"
        r")$"
    )

    TS_TYPE_KEYWORDS = {
        "string",
        "number",
        "boolean",
        "object",
        "any",
        "unknown",
        "never",
        "void",
        "null",
        "undefined",
    }

    REFERENCE_VALUE_RE = re.compile(
        r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+(?:\s*(?:\?\?|\|\|)\s*[A-Za-z_][A-Za-z0-9_\.]*)?$"
    )

    FUNCTION_CALL_RE = re.compile(
        r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\([^)]*\)$"
    )

    SIMPLE_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

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

        full_fragment = match.group(0).strip()
        if not full_fragment:
            return None

        if match.lastindex and match.lastindex >= 2:
            variable_name = (match.group(1) or "").strip()
            value = (match.group(2) or "").strip().rstrip(",;")
            if not variable_name or not value:
                return None

            if self._is_non_secret_value(
                value=value,
                variable_name=variable_name,
                secret_name=secret_name,
                full_line=match.string,
            ):
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

    def _is_non_secret_value(
        self,
        value: str,
        variable_name: str,
        secret_name: str,
        full_line: str | None = None,
    ) -> bool:
        normalized = value.strip().strip("'\"")
        lowered = normalized.lower()
        variable_lower = variable_name.lower()
        line = (full_line or "").strip()

        if "${{" in line and "secrets." in line and "}}" in line:
            return True

        if normalized.startswith("${{") or normalized.startswith("${"):
            return True

        if any(pattern.fullmatch(normalized) for pattern in self.ENV_REFERENCE_PATTERNS):
            return True

        if secret_name == "Password" and "hashed" in variable_lower:
            return True

        if self.PLACEHOLDER_VALUE_RE.fullmatch(lowered):
            return True

        if lowered in self.TS_TYPE_KEYWORDS:
            return True

        if self.REFERENCE_VALUE_RE.fullmatch(normalized):
            return True

        if self.FUNCTION_CALL_RE.fullmatch(normalized):
            return True

        if self.SIMPLE_IDENTIFIER_RE.fullmatch(normalized):
            return True

        return False