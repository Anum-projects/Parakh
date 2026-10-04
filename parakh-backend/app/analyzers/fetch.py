"""Safe page fetching: manual redirect following with SSRF protection on every hop."""
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

import httpx

from ..findings import Finding
from .domain_analysis import is_public_ip, resolve
from .url_analysis import ParsedURL

MAX_BYTES = 500_000
MAX_REDIRECTS = 5
HEADERS = {"User-Agent": "ParakhBot/1.0 (link verification; read-only)"}


@dataclass
class FetchResult:
    chain: list[str]
    final_url: str
    status: int | None = None
    html: str | None = None
    error: str | None = None
    blocked: bool = False

    @property
    def ok(self) -> bool:
        return self.error is None and self.status is not None


async def _get(client: httpx.AsyncClient, url: str):
    """Returns (redirect_url | None, status, html)."""
    async with client.stream("GET", url) as r:
        if r.is_redirect and r.headers.get("location"):
            return urljoin(url, r.headers["location"]), r.status_code, None
        html = None
        if "html" in r.headers.get("content-type", "").lower():
            buf = bytearray()
            async for chunk in r.aiter_bytes():
                buf.extend(chunk)
                if len(buf) > MAX_BYTES:
                    break
            html = bytes(buf).decode(r.encoding or "utf-8", errors="replace")
        return None, r.status_code, html


async def fetch_page(url: str) -> FetchResult:
    chain = [url]
    current = url
    timeout = httpx.Timeout(8.0)
    async with httpx.AsyncClient(follow_redirects=False, timeout=timeout, headers=HEADERS) as client, \
            httpx.AsyncClient(follow_redirects=False, timeout=timeout, headers=HEADERS, verify=False) as lax:
        for _ in range(MAX_REDIRECTS + 1):
            host = urlsplit(current).hostname or ""
            ips = await resolve(host)
            if not ips:
                return FetchResult(chain, current, error="unresolved")
            if not all(is_public_ip(i) for i in ips):
                return FetchResult(chain, current, error="blocked_private", blocked=True)
            try:
                try:
                    nxt, status, html = await _get(client, current)
                except httpx.ConnectError as e:
                    if "CERTIFICATE" not in str(e).upper():
                        raise
                    # Bad certificate: still read the page (GET only, nothing is submitted).
                    nxt, status, html = await _get(lax, current)
            except httpx.HTTPError as e:
                return FetchResult(chain, current, error=type(e).__name__)
            if nxt is None:
                return FetchResult(chain, current, status=status, html=html)
            if urlsplit(nxt).scheme not in ("http", "https"):
                return FetchResult(chain, current, error="bad_redirect")
            chain.append(nxt)
            current = nxt
        return FetchResult(chain, current, error="too_many_redirects")


def redirect_findings(original: ParsedURL, final: ParsedURL | None, fetch: FetchResult) -> list[Finding]:
    out: list[Finding] = []
    hops = len(fetch.chain) - 1
    if hops > 3:
        out.append(Finding("many_redirects", 10, f"The link redirects {hops} times before reaching a page",
                           f"لنک کسی صفحے تک پہنچنے سے پہلے {hops} بار redirect ہوتا ہے", "redirect"))
    if fetch.blocked and hops > 0:
        out.append(Finding("redirect_internal", 25, "The link redirects to an internal/private address",
                           "لنک کسی اندرونی/نجی ایڈریس پر redirect کرتا ہے", "redirect"))
    if final and final.registered_domain != original.registered_domain \
            and original.registered_domain not in _shorteners():
        out.append(Finding("cross_domain_redirect", 15,
                           f"The link sends you to a different website ({final.registered_domain})",
                           f"لنک آپ کو ایک مختلف ویب سائٹ ({final.registered_domain}) پر لے جاتا ہے", "redirect"))
    return out


def _shorteners():
    from .url_analysis import SHORTENERS
    return SHORTENERS
