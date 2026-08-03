"""
Mock CTI adapters used when API keys are absent (CTI_MOCK=true).
Returns structurally correct, plausible-looking responses for local dev.
Scores are calibrated to match real-world CTI signal strength so that
genuinely phishing-like URLs reach the malicious threshold (≥0.65).
"""
import re
from cti.base import BaseCTIAdapter, CTIResponse
from shared.constants import SUSPICIOUS_KEYWORDS, HIGH_RISK_TLDS

_IP_RE = re.compile(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
_TOTAL_ENGINES = 72


def _keyword_count(url: str) -> int:
    low = url.lower()
    return sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in low)


def _has_ip(url: str) -> bool:
    return bool(_IP_RE.match(url))


def _has_risky_tld(url: str) -> bool:
    low = url.lower()
    return any(low.split("?")[0].split("/")[2].endswith(tld) for tld in HIGH_RISK_TLDS
               if len(url.split("/")) > 2)


class MockVirusTotalAdapter(BaseCTIAdapter):
    async def lookup(self, url: str) -> CTIResponse:
        kw = _keyword_count(url)
        if _has_ip(url) or kw >= 2:
            malicious = 45   # ~62% engines flagged — strong signal
        elif kw == 1:
            malicious = 12   # ~17% engines flagged — moderate signal
        else:
            malicious = 0
        hit = malicious > 0
        score = round(malicious / _TOTAL_ENGINES, 4)
        return CTIResponse(
            source="virustotal",
            hit=hit,
            score=score,
            details={
                "stats": {"malicious": malicious, "harmless": _TOTAL_ENGINES - malicious, "suspicious": 0},
                "malicious_count": malicious,
                "total_engines": _TOTAL_ENGINES,
                "mock": True,
            },
        )


class MockURLhausAdapter(BaseCTIAdapter):
    async def lookup(self, url: str) -> CTIResponse:
        kw = _keyword_count(url)
        if _has_ip(url) or (_has_risky_tld(url) and kw >= 1):
            score = 1.0
        elif kw >= 2:
            score = 0.8
        elif kw == 1:
            score = 0.3
        else:
            score = 0.0
        hit = score > 0.0
        return CTIResponse(
            source="urlhaus",
            hit=hit,
            score=score,
            details={"query_status": "is_db" if hit else "no_results", "mock": True},
        )


class MockWHOISAdapter(BaseCTIAdapter):
    async def lookup(self, url: str) -> CTIResponse:
        if _has_ip(url):
            age, score = 0, 1.0
        elif _has_risky_tld(url):
            age, score = 12, 1.0
        elif _keyword_count(url) >= 2:
            age, score = 45, 0.8
        else:
            age, score = 730, 0.0
        hit = score > 0.0
        return CTIResponse(
            source="whois",
            hit=hit,
            score=score,
            details={
                "domain_age_days": age,
                "registrar": "Mock Registrar LLC",
                "creation_date": "2022-01-01 00:00:00+00:00",
                "country": "US",
                "mock": True,
            },
        )
