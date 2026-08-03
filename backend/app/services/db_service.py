import json
import uuid
from datetime import datetime, timezone
from typing import List

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import ScanRecord
from app.models.scan import ScanResult
from app.models.threat import RiskLevel


class DBService:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def save_scan(self, result: ScanResult) -> ScanResult:
        record = ScanRecord(
            id=result.id or str(uuid.uuid4()),
            url=result.url,
            score=result.score,
            level=result.level.value if isinstance(result.level, RiskLevel) else result.level,
            ml_probability=result.ml_probability,
            indicators_json=json.dumps([i.model_dump() for i in result.indicators]),
            explanation_json=json.dumps(result.explanation),
            cti_json=json.dumps(result.cti.model_dump() if result.cti else {}),
            features_json=json.dumps(result.features.model_dump() if result.features else {}),
            source=result.source,
            scanned_at=result.scanned_at or datetime.now(timezone.utc),
        )
        self.session.add(record)
        await self.session.commit()
        await self.session.refresh(record)
        result.id = record.id
        return result

    async def get_history(self, limit: int = 50, offset: int = 0) -> List[ScanResult]:
        stmt = (
            select(ScanRecord)
            .order_by(ScanRecord.scanned_at.desc())
            .limit(limit)
            .offset(offset)
        )
        rows = (await self.session.execute(stmt)).scalars().all()
        return [_record_to_result(r) for r in rows]


def _record_to_result(r: ScanRecord) -> ScanResult:
    from app.models.scan import URLFeatures, CTIResult
    from app.models.threat import ThreatIndicator

    indicators = [ThreatIndicator(**i) for i in json.loads(r.indicators_json or "[]")]
    features_data = json.loads(r.features_json or "{}")
    features = URLFeatures(**features_data) if features_data else None
    cti_data = json.loads(r.cti_json or "{}")
    cti = CTIResult(**cti_data) if cti_data else None

    return ScanResult(
        id=r.id,
        url=r.url,
        score=r.score,
        level=RiskLevel(r.level),
        ml_probability=r.ml_probability,
        features=features,
        cti=cti,
        indicators=indicators,
        explanation=json.loads(r.explanation_json or "[]"),
        scanned_at=r.scanned_at,
        source=r.source,
    )
