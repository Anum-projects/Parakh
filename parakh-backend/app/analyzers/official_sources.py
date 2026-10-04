"""Official-source verification: compare a link against a list of trusted organizations."""
import json
import re
from pathlib import Path

_DATA = json.loads((Path(__file__).resolve().parent.parent / "data" / "trusted_domains.json").read_text(encoding="utf-8"))
ORGS: list[dict] = _DATA["organizations"]
OFFICIAL_DOMAINS: set[str] = {d for o in ORGS for d in o["domains"]}


def is_official(registered_domain: str) -> bool:
    return registered_domain.lower() in OFFICIAL_DOMAINS


def orgs_claimed_in_host(host: str, registered_domain: str) -> list[dict]:
    """Orgs whose keyword appears in the hostname although the domain is not theirs."""
    host = host.lower()
    tokens = set(re.split(r"[.\-_]", host))
    hits = []
    for org in ORGS:
        if registered_domain in org["domains"]:
            continue
        for kw in org["keywords"]:
            if kw in tokens or (len(kw) >= 5 and kw in host):
                hits.append(org)
                break
    return hits


def orgs_mentioned_in_text(text: str, registered_domain: str) -> list[dict]:
    """Orgs named in page title/headings although the domain is not theirs."""
    hits = []
    for org in ORGS:
        if registered_domain in org["domains"]:
            continue
        for name in org["names"]:
            if re.search(r"(?<!\w)" + re.escape(name) + r"(?!\w)", text, re.IGNORECASE):
                hits.append(org)
                break
    return hits
