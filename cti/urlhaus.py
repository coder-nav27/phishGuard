"""URLhaus (abuse.ch) adapter — no API key required."""
import httpx
from cti.base import BaseCTIAdapter, CTIResponse

URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/url/"

# Threat type → risk score (abuse.ch threat taxonomy)
_THREAT_SCORES: dict[str, float] = {
    "malware_download": 1.0,
    "phishing": 1.0,
    "botnet_cc": 0.9,
    "ransomware": 1.0,
    "exploit": 0.9,
    "coinminer": 0.7,
}


class URLhausAdapter(BaseCTIAdapter):
    async def lookup(self, url: str) -> CTIResponse:
        try:
            async with httpx.AsyncClient(timeout=12.0) as client:
                resp = await client.post(URLHAUS_API, data={"url": url})
            data = resp.json()
            in_db = data.get("query_status") == "is_db"
            threat = data.get("threat") or ""
            score = _THREAT_SCORES.get(threat.lower(), 0.8) if in_db else 0.0
            return CTIResponse(
                source="urlhaus",
                hit=in_db,
                score=score,
                details={
                    "query_status": data.get("query_status"),
                    "threat": threat or None,
                    "tags": data.get("tags", []),
                    "date_added": data.get("date_added"),
                    "url_status": data.get("url_status"),
                } if in_db else {"query_status": data.get("query_status")},
            )
        except Exception as exc:
            return CTIResponse(source="urlhaus", hit=False, score=0.0, details={}, error=str(exc))
