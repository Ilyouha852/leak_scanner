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
        "regex": re.compile(
            r"(?i)\b([A-Za-z_][A-Za-z0-9_\-]*(?:password|pwd|secret)[A-Za-z0-9_\-]*)\b\s*[=:]\s*['\"]?([^'\"\s]+)['\"]?"
        ),
        "risk": "medium",
    },
    "Generic API key": {
        "regex": re.compile(
            r"(?i)\b([A-Za-z_][A-Za-z0-9_\-]*(?:api[_-]?key|apikey|token|secret)[A-Za-z0-9_\-]*)\b\s*[=:]\s*['\"]?([A-Za-z0-9_\-+/=]{20,})['\"]?"
        ),
        "risk": "low",
    },
}