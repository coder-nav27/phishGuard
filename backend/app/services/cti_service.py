import sys
from pathlib import Path
import asyncio
from typing import List

_REPO_ROOT = Path(__file__).resolve().parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from app.config import settings
from cti.base import CTIResponse  # noqa: E402


def _get_adapters():
    if settings.cti_mock or not settings.virustotal_api_key:
        from cti.mock_adapters import MockVirusTotalAdapter, MockURLhausAdapter, MockWHOISAdapter
        return [MockVirusTotalAdapter(), MockURLhausAdapter(), MockWHOISAdapter()]
    from cti.virustotal import VirusTotalAdapter
    from cti.urlhaus import URLhausAdapter
    from cti.whois_lookup import WHOISAdapter
    return [
        VirusTotalAdapter(settings.virustotal_api_key),
        URLhausAdapter(),
        WHOISAdapter(),
    ]


async def enrich(url: str) -> List[CTIResponse]:
    adapters = _get_adapters()
    results = await asyncio.gather(*[a.lookup(url) for a in adapters], return_exceptions=True)
    return [r for r in results if isinstance(r, CTIResponse)]
