from __future__ import annotations
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime

from app.models.threat import RiskLevel, ThreatIndicator


class ScanRequest(BaseModel):
    url: str
    source: str = "api"   # "api" | "extension" | "dashboard"


class URLFeatures(BaseModel):
    url_length: int
    domain_length: int
    subdomain_count: int
    has_ip: bool
    uses_https: bool
    dot_count: int
    hyphen_count: int
    at_sign_count: int
    special_char_count: int
    digit_ratio: float
    entropy: float
    suspicious_keywords: int
    is_url_shortener: bool
    tld_risk: float
    path_depth: int
    query_param_count: int
    has_encoded_chars: bool
    double_slash_in_path: bool
    has_port: bool
    is_punycode: bool
    tilde_in_path: bool
    hex_in_domain: bool
    redirect_double_slash: bool
    domain_digit_count: int
    url_shortener_flag: int
    brand_count: int
    num_dots_in_path: int
    query_length: int
    fragment_present: bool
    multi_subdomain: int


class CTIResult(BaseModel):
    virustotal: Optional[Dict[str, Any]] = None
    urlhaus: Optional[Dict[str, Any]] = None
    whois: Optional[Dict[str, Any]] = None
    enriched: bool = False


class ScanResult(BaseModel):
    id: Optional[str] = None
    url: str
    score: float
    level: RiskLevel
    ml_probability: float
    features: Optional[URLFeatures] = None
    cti: Optional[CTIResult] = None
    indicators: List[ThreatIndicator] = []
    explanation: List[str] = []
    scanned_at: Optional[datetime] = None
    source: str = "api"

    model_config = {"from_attributes": True}
