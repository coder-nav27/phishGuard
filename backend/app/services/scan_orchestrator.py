"""Coordinates feature extraction, ML inference, CTI enrichment, and persistence."""
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncSession

_REPO_ROOT = Path(__file__).resolve().parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from app.models.scan import ScanRequest, ScanResult, CTIResult
from app.models.threat import RiskLevel, ThreatIndicator
from app.services.feature_service import extract
from app.services.ml_service import MLService
from app.services.cti_service import enrich
from app.services.db_service import DBService

from cti.risk_scorer import compute_risk_score  # noqa: E402
from ml.features.obfuscation import detect_obfuscation_signals  # noqa: E402
from ml.features.typosquatting import check_typosquatting  # noqa: E402
import urllib.parse


async def orchestrate_scan(request: ScanRequest, session: AsyncSession) -> ScanResult:
    url = request.url

    # 1. Feature extraction
    features, vector = extract(url)

    # 2. ML inference
    ml_prob = MLService.predict(vector)

    # 3. Parallel CTI enrichment
    cti_responses = await enrich(url)

    # 4. Risk score aggregation
    score, level_str, explanation = compute_risk_score(ml_prob, cti_responses)

    # 5. Build indicators
    indicators = _build_indicators(url, features, ml_prob, cti_responses)

    # 6. Build CTI result dict
    cti_map = {r.source: r.details for r in cti_responses}
    cti_result = CTIResult(
        virustotal=cti_map.get("virustotal"),
        urlhaus=cti_map.get("urlhaus"),
        whois=cti_map.get("whois"),
        enriched=len(cti_responses) > 0,
    )

    result = ScanResult(
        id=str(uuid.uuid4()),
        url=url,
        score=score,
        level=RiskLevel(level_str),
        ml_probability=ml_prob,
        features=features,
        cti=cti_result,
        indicators=indicators,
        explanation=explanation,
        scanned_at=datetime.now(timezone.utc),
        source=request.source,
    )

    db = DBService(session)
    return await db.save_scan(result)


def _build_indicators(url, features, ml_prob, cti_responses) -> list[ThreatIndicator]:
    indicators = []

    if ml_prob > 0.7:
        indicators.append(ThreatIndicator(
            type="ml_high_confidence",
            severity="high",
            description=f"ML classifier: {ml_prob:.1%} phishing probability",
            source="ml",
        ))
    elif ml_prob > 0.5:
        indicators.append(ThreatIndicator(
            type="ml_flag",
            severity="medium",
            description=f"ML classifier flagged URL ({ml_prob:.1%} probability)",
            source="ml",
        ))

    if features.has_ip:
        indicators.append(ThreatIndicator(
            type="ip_in_url",
            severity="high",
            description="URL uses raw IP address instead of domain name",
            source="feature",
        ))

    if features.suspicious_keywords > 0:
        indicators.append(ThreatIndicator(
            type="suspicious_keywords",
            severity="medium",
            description=f"{features.suspicious_keywords} phishing keyword(s) found in URL",
            source="feature",
        ))

    if features.tld_risk > 0:
        indicators.append(ThreatIndicator(
            type="high_risk_tld",
            severity="medium",
            description="URL uses a high-risk top-level domain",
            source="feature",
        ))

    domain = urllib.parse.urlparse(url).netloc.replace("www.", "")
    typo = check_typosquatting(domain)
    if typo["is_typosquatting"]:
        indicators.append(ThreatIndicator(
            type="typosquatting",
            severity="high",
            description=f"Possible typosquatting of '{typo['closest_brand']}' (edit distance {typo['edit_distance']})",
            source="feature",
            value=typo["closest_brand"],
        ))

    obf = detect_obfuscation_signals(url)
    for sig in obf:
        indicators.append(ThreatIndicator(
            type=f"obfuscation_{sig}",
            severity="high",
            description=f"Obfuscation technique detected: {sig.replace('_', ' ')}",
            source="feature",
        ))

    for cti in cti_responses:
        if cti.hit:
            sev = "critical" if cti.source == "urlhaus" else "high"
            indicators.append(ThreatIndicator(
                type=f"{cti.source}_hit",
                severity=sev,
                description=f"URL flagged by {cti.source} (score: {cti.score:.0%})",
                source=cti.source,
            ))

    return indicators
