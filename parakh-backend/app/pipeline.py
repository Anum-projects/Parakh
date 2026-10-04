"""Orchestrates all analysis layers for one URL."""
import asyncio

from . import llm, scoring
from .analyzers.content_analysis import analyze_html, content_findings
from .analyzers.domain_analysis import domain_age_days, domain_findings, is_public_ip, resolve, ssl_check
from .analyzers.fetch import FetchResult, fetch_page, redirect_findings
from .analyzers.official_sources import is_official
from .analyzers.reputation import reputation_findings, safe_browsing_hit
from .analyzers.url_analysis import InvalidURL, parse_url, url_findings
from .config import settings
from .findings import Finding
from .schemas import AnalyzeResponse, Reason

DISCLAIMER = {
    "en": "Parakh gives a risk assessment based on available signals. It is not a guarantee that a link is safe or fake. When in doubt, verify through the organization's official channels.",
    "ur": "پرکھ دستیاب علامات کی بنیاد پر خطرے کا اندازہ دیتا ہے۔ یہ اس بات کی ضمانت نہیں کہ لنک محفوظ یا جعلی ہے۔ شک ہو تو ادارے کے سرکاری ذرائع سے تصدیق کریں۔",
}


class BlockedTarget(ValueError):
    pass


async def _none():
    return None


async def analyze(raw_url: str, lang: str = "en") -> AnalyzeResponse:
    p = parse_url(raw_url)  # raises InvalidURL
    findings: list[Finding] = url_findings(p)

    ips = await resolve(p.host)
    if ips and not all(is_public_ip(i) for i in ips):
        raise BlockedTarget("Links pointing to private or internal addresses cannot be checked.")

    # Stage 1: independent checks in parallel
    age, ssl_info, fetch = await asyncio.gather(
        domain_age_days(p.registered_domain) if not p.is_ip else _none(),
        ssl_check(p.host, p.port) if (p.is_https and ips) else _none(),
        fetch_page(p.url) if ips else _none(),
    )
    if fetch is None:
        fetch = FetchResult([p.url], p.url, error="unresolved")
    findings += domain_findings(age, bool(ips), ssl_info)

    # Redirect handling: analyse where the link really ends up
    final = None
    final_age = None
    if fetch.final_url != p.url:
        try:
            final = parse_url(fetch.final_url)
        except InvalidURL:
            final = None
    effective = p
    if final and final.registered_domain != p.registered_domain:
        effective = final
        final_age = await domain_age_days(final.registered_domain) if not final.is_ip else None
        scope = ("final_", "After redirect: ", "ری ڈائریکٹ کے بعد: ")
        for f in url_findings(final) + domain_findings(final_age, True, None):
            findings.append(f.scoped(*scope))
    findings += redirect_findings(p, final, fetch)

    # Content
    info = None
    if fetch.html:
        info = analyze_html(fetch.html, fetch.final_url, effective.registered_domain)
        findings += content_findings(info)

    # Reputation + official source
    hit = await safe_browsing_hit(fetch.chain)
    findings += reputation_findings(hit)
    official = is_official(effective.registered_domain)
    if official:
        findings.append(Finding("official_domain", -40,
                                "The domain matches a known official domain",
                                "ڈومین ایک معلوم سرکاری ڈومین سے مطابقت رکھتا ہے", "official"))

    # Confidence is based on how many applicable checks actually worked
    checks = {"dns": bool(ips), "page": fetch.ok}
    if not p.is_ip:
        checks["whois"] = age is not None
    if p.is_https and ips:
        checks["ssl"] = bool(ssl_info and ssl_info.get("checked"))
    if settings.safe_browsing_key:
        checks["reputation"] = hit is not None

    score, level, confidence, used = scoring.compute(findings, checks, official, bool(hit))

    idx = "ur" if lang == "ur" else "en"
    def to_reason(f: Finding) -> Reason:
        return Reason(code=f.code, severity=f.severity, text=f.ur if idx == "ur" else f.en)

    risky = sorted([f for f in used if f.weight > 0 or f.code == "insufficient_data"], key=lambda f: -f.weight)
    good = [f for f in used if f.weight < 0]

    signals = {
        "host": p.host,
        "registered_domain": p.registered_domain,
        "domain_age_days": age,
        "ssl": ssl_info,
        "redirect_count": len(fetch.chain) - 1,
        "final_url": fetch.final_url,
        "http_status": fetch.status,
        "fetch_error": fetch.error,
        "page_title": info.title if info else None,
        "has_form": info.has_form if info else None,
        "official_domain": official,
        "safe_browsing": "unavailable" if hit is None else ("listed" if hit else "not_listed"),
    }

    reasons_en = [f.en for f in risky]
    positives_en = [f.en for f in good]
    explanation, source = await llm.explain(level, score, confidence, reasons_en, positives_en, signals, idx)

    return AnalyzeResponse(
        input_url=p.url, final_url=fetch.final_url, risk_level=level, score=score, confidence=confidence,
        reasons=[to_reason(f) for f in risky], positives=[to_reason(f) for f in good],
        recommendation=scoring.recommendation(level, confidence, idx),
        explanation=explanation, explanation_source=source, signals=signals, disclaimer=DISCLAIMER[idx],
    )
