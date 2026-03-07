"""Расчет энтропии Шеннона."""

from __future__ import annotations

import math
from collections import Counter


class EntropyCalculator:
    """Калькулятор энтропии текста по формуле Шеннона."""

    @staticmethod
    def calculate_entropy(text: str) -> float:
        """
        Вычисляет энтропию строки:
        H = -Σ p(x) * log2(p(x))
        """
        if not text:
            return 0.0

        counts = Counter(text)
        length = len(text)
        entropy = 0.0

        for count in counts.values():
            probability = count / length
            entropy -= probability * math.log2(probability)

        return entropy