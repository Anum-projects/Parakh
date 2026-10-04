"""Layer 1: rule-based URL validation and structure analysis."""
import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

import tldextract

from ..findings import Finding
from .official_sources import orgs_claimed_in_host

_extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)  # bundled suffix list, no network

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
    "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "bit.do", "s.id", "t.ly", "lnkd.in",
}
SUSPICIOUS_TLDS = {
    "xyz", "top", "click", "buzz", "icu", "tk", "ml", "ga", "cf", "gq", "work", "rest",
    "monster", "cyou", "sbs", "cfd", "loan", "zip", "mov",
}
SCAM_KEYWORDS = [
    "free", "claim", "bonus", "prize", "winner", "register", "apply", "verify", "login",
    "otp", "scholarship", "ehsaas", "benazir", "ramadan", "package", "reward", "giveaway",
    "cnic", "loan", "grant", "subsidy", "urgent",
]


def registered_domain_of(host: str) -> str:
    """Registrable domain (e.g. hec.gov.pk). Works across tldextract versions."""
    ext = _extract(host)
    return getattr(ext, "top_domain_under_public_suffix", None) or ext.registered_domain or host


class InvalidURL(ValueError):
    pass


@dataclass
class ParsedURL:
    url: str
    scheme: str
    host: str
    port: int | None
    path_query: str
    registered_domain: str
    subdomain: str
    suffix: str
    is_ip: bool
    has_userinfo: bool
    had_scheme: bool

    @property
    def is_https(self) -> bool:
        return self.scheme == "https"


def parse_url(raw: str) -> ParsedURL:
    raw = (raw or "").strip()
    if not raw:
        raise InvalidURL("Please enter a link.")
    if len(raw) > 2048:
        raise InvalidURL("The link is too long.")
    if re.search(r"\s", raw):
        raise InvalidURL("The link must not contain spaces.")
    had_scheme = "://" in raw
    url = raw if had_scheme else "https://" + raw
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        raise InvalidURL("This does not look like a valid link.")
    if parts.scheme not in ("http", "https"):
        raise InvalidURL("Only http and https links can be checked.")
    host = (parts.hostname or "").rstrip(".")
    if not host:
        raise InvalidURL("This does not look like a valid link.")

    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        pass

    if not is_ip:
        if "." not in host:
            raise InvalidURL("The link must contain a valid domain name, e.g. example.com.")
        try:
            host = host.encode("idna").decode("ascii")  # unicode -> punycode
        except UnicodeError:
            raise InvalidURL("The domain name is not valid.")
        ext = _extract(host)
        registered, sub, suffix = registered_domain_of(host), ext.subdomain, ext.suffix
    else:
        registered, sub, suffix = host, "", ""

    path_query = parts.path + ("?" + parts.query if parts.query else "")
    return ParsedURL(url, parts.scheme, host.lower(), port, path_query, registered.lower(), sub.lower(),
                     suffix.lower(), is_ip, parts.username is not None, had_scheme)


def url_findings(p: ParsedURL) -> list[Finding]:
    out: list[Finding] = []
    add = out.append

    if p.is_ip:
        add(Finding("ip_host", 25, "The link uses a raw IP address instead of a website name",
                    "لنک ویب سائٹ کے نام کے بجائے براہِ راست IP ایڈریس استعمال کرتا ہے"))
    if p.registered_domain in SHORTENERS:
        add(Finding("shortener", 15, "The link is shortened, so the real destination is hidden",
                    "لنک مختصر (shortened) ہے، اس لیے اصل منزل چھپی ہوئی ہے"))
    if "xn--" in p.host:
        add(Finding("punycode", 25, "The domain uses special characters that can imitate a real website name",
                    "ڈومین میں خاص حروف ہیں جو کسی اصل ویب سائٹ کی نقل کر سکتے ہیں"))
    if p.has_userinfo:
        add(Finding("userinfo", 20, "The link contains an '@' section, a common trick to disguise the real site",
                    "لنک میں '@' موجود ہے، جو اصل ویب سائٹ چھپانے کا عام طریقہ ہے"))
    if not p.is_ip and p.subdomain and p.subdomain.count(".") + 1 >= 3:
        add(Finding("deep_subdomain", 10, "The link has an unusually long chain of subdomains",
                    "لنک میں سب ڈومینز کی غیر معمولی لمبی زنجیر ہے"))
    if p.host.count("-") >= 3:
        add(Finding("many_hyphens", 10, "The domain name contains many hyphens",
                    "ڈومین کے نام میں بہت سے ہائفن (-) ہیں"))
    if p.suffix.split(".")[-1] in SUSPICIOUS_TLDS and not p.is_ip:
        add(Finding("suspicious_tld", 12, f"The domain ends in '.{p.suffix}', which is often used in scam sites",
                    f"ڈومین '.{p.suffix}' پر ختم ہوتا ہے، جو اکثر فراڈ ویب سائٹس میں استعمال ہوتا ہے"))
    if p.port not in (None, 80, 443):
        add(Finding("odd_port", 10, f"The link uses an unusual port ({p.port})",
                    f"لنک غیر معمولی پورٹ ({p.port}) استعمال کرتا ہے"))
    if p.had_scheme and not p.is_https:
        add(Finding("no_https", 15, "The link does not use HTTPS, so data sent to it is not encrypted",
                    "لنک HTTPS استعمال نہیں کرتا، اس لیے بھیجا گیا ڈیٹا انکرپٹڈ نہیں ہوگا"))
    if len(p.url) > 100:
        add(Finding("long_url", 5, "The link is unusually long", "لنک غیر معمولی طور پر لمبا ہے"))

    haystack = (p.host + p.path_query).lower()
    hits = [k for k in SCAM_KEYWORDS if k in haystack]
    if hits:
        shown = ", ".join(hits[:4])
        add(Finding("scam_keywords", min(6 * len(hits), 16),
                    f"The link contains words common in scam links ({shown})",
                    f"لنک میں ایسے الفاظ ہیں جو فراڈ لنکس میں عام ہیں ({shown})"))

    if not p.is_ip:
        for org in orgs_claimed_in_host(p.host, p.registered_domain):
            add(Finding("org_impersonation", 35,
                        f"The domain mentions {org['name']} but is not one of its official domains",
                        f"ڈومین میں {org['name']} کا نام ہے مگر یہ اس کا سرکاری ڈومین نہیں ہے",
                        "official"))
    return out
