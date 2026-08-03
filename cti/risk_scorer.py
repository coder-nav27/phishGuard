"""Aggregate ML probability + CTI signals into a single risk score."""
from cti.base import CTIResponse
from typing import List

# Must sum to 1.0
WEIGHTS = {"ml": 0.40, "virustotal": 0.30, "urlhaus": 0.20, "whois": 0.10}


def compute_risk_score(
    ml_probability: float,
    cti_results: List[CTIResponse],
) -> tuple[float, str, list[str]]:
    """Returns (score 0-1, level string, explanation bullets)."""
    by_source = {r.source: r for r in cti_results}

    def get(source: str) -> float:
        return by_source[source].score if source in by_source else 0.0

    score = (
        WEIGHTS["ml"]         * ml_probability
        + WEIGHTS["virustotal"] * get("virustotal")
        + WEIGHTS["urlhaus"]    * get("urlhaus")
        + WEIGHTS["whois"]      * get("whois")
    )
    score = round(min(float(score), 1.0), 4)

    level = "safe" if score < 0.30 else ("suspicious" if score < 0.65 else "malicious")

    explanation = []
    if ml_probability > 0.5:
        explanation.append(
            f"ML classifier: {ml_probability:.1%} phishing probability"
        )
    vt = by_source.get("virustotal")
    if vt and vt.hit:
        cnt = vt.details.get("malicious_count", "?")
        total = vt.details.get("total_engines", "?")
        explanation.append(f"VirusTotal: {cnt}/{total} engines flagged as malicious")
    uh = by_source.get("urlhaus")
    if uh and uh.hit:
        explanation.append("URL matches URLhaus malware/phishing database (abuse.ch)")
    ws = by_source.get("whois")
    if ws and ws.hit:
        age = ws.details.get("domain_age_days")
        explanation.append(
            f"Domain is only {age} days old — newly registered domains carry elevated risk"
        )

    return score, level, explanation
