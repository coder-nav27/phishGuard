from pydantic import BaseModel
from enum import Enum
from typing import Optional


class RiskLevel(str, Enum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"


class ThreatIndicator(BaseModel):
    type: str
    severity: str       # "low" | "medium" | "high" | "critical"
    description: str
    source: str         # "ml" | "virustotal" | "urlhaus" | "whois" | "feature"
    value: Optional[str] = None
