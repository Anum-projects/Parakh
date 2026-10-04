"""Layer 4b: threat-intelligence lookup (Google Safe Browsing). Optional: needs an API key."""
import httpx

from ..config import settings
from ..findings import Finding

ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"


async def safe_browsing_hit(urls: list[str]) -> bool | None:
    """True = listed, False = not listed, None = check unavailable."""
    if not settings.safe_browsing_key:
        return None
    body = {
        "client": {"clientId": "parakh", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in urls[:5]],
        },
    }
    try:
        async with httpx.AsyncClient(timeout=6) as client:
            r = await client.post(ENDPOINT, params={"key": settings.safe_browsing_key}, json=body)
        r.raise_for_status()
        return bool(r.json().get("matches"))
    except (httpx.HTTPError, ValueError):
        return None


def reputation_findings(hit: bool | None) -> list[Finding]:
    if hit:
        return [Finding("blocklisted", 80, "The link is listed by Google Safe Browsing as dangerous",
                        "لنک Google Safe Browsing کی خطرناک فہرست میں شامل ہے", "reputation")]
    return []
