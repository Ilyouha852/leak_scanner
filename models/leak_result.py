from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(slots=True)
class LeakResult:

    file_path: str
    line_number: int
    code_fragment: str
    secret_type: str
    risk_level: str
    detector_type: str

    def to_dict(self) -> dict:
        return asdict(self)