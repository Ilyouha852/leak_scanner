"""Конфигурация регулярных паттернов для поиска секретов."""

from __future__ import annotations

import re


SECRET_PATTERNS: dict[str, dict[str, object]] = {
    "AWS Access Key": {
    "regex": re.compile(r"AKIA[0-9A-Z]{16}"),
    "risk": "high",
    },
    "GitHub Token": {
    "regex": re.compile(r"ghp_[0-9A-Za-z]{36}"),
    "risk": "high",
    },
    "Private Key": {
    "regex": re.compile(r"-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----"),
    "risk": "high",
    },
    "Password": {
    "regex": re.compile(r"(?i)(password|pwd|secret)\s*[=:]\s*['\"]?[^'\"\s]{4,}['\"]?"),
    "risk": "medium",
    },
    "Generic API key": {
    "regex": re.compile(r"[a-zA-Z0-9_-]{20,}"),
    "risk": "low",
    },
}
