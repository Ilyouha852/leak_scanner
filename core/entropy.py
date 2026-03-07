from __future__ import annotations

import math
from collections import Counter


class EntropyCalculator:

    @staticmethod
    def calculate_entropy(text: str) -> float:
        if not text:
            return 0.0

        counts = Counter(text)
        length = len(text)
        entropy = 0.0

        for count in counts.values():
            probability = count / length
            entropy -= probability * math.log2(probability)

        return entropy