from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class CTIResponse:
    source: str
    hit: bool
    score: float          # 0.0 – 1.0; higher = more malicious
    details: dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None


class BaseCTIAdapter(ABC):
    @abstractmethod
    async def lookup(self, url: str) -> CTIResponse: ...
