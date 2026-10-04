"""Layer 3: page content analysis (forms, sensitive-data requests, payment and urgency wording)."""
import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup

from ..findings import Finding
from .official_sources import orgs_mentioned_in_text
from .url_analysis import registered_domain_of

SENSITIVE_RE = re.compile(r"\b(cnic|nic|national\s*id|identity\s*card|otp|one[\s-]*time|pin\s*code|cvv|card\s*number|"
                          r"account\s*number|iban|bank\s*account|شناختی)\b", re.I)
PAYMENT_RE = re.compile(r"(easypaisa|jazzcash|sadapay|nayapay|processing\s*fee|registration\s*fee|"
                        r"application\s*fee|advance\s*payment|send\s*money|pay\s*now|ایزی\s*پیسہ|جیز\s*کیش)", re.I)
URGENCY_RE = re.compile(r"(limited\s*time|hurry|last\s*chance|expires?\s*(today|soon)|act\s*now|only\s*today|"
                        r"urgent|آخری\s*موقع|فوری)", re.I)


@dataclass
class ContentInfo:
    title: str = ""
    has_form: bool = False
    has_password_field: bool = False
    asks_sensitive: bool = False
    asks_payment: bool = False
    urgency: bool = False
    cross_domain_form: bool = False
    org_mentions: list = None


def analyze_html(html: str, final_url: str, registered_domain: str) -> ContentInfo:
    soup = BeautifulSoup(html, "html.parser")
    info = ContentInfo(org_mentions=[])
    info.title = (soup.title.get_text(" ", strip=True) if soup.title else "")[:150]

    heading_text = " ".join(h.get_text(" ", strip=True) for h in soup.find_all(["h1", "h2"])[:6])
    meta = soup.find("meta", attrs={"name": "description"})
    meta_text = meta.get("content", "") if meta else ""
    info.org_mentions = orgs_mentioned_in_text(f"{info.title} {heading_text} {meta_text}", registered_domain)

    forms = soup.find_all("form")
    info.has_form = bool(forms)
    form_blob = []
    for f in forms:
        for inp in f.find_all(["input", "select", "textarea", "label"]):
            if inp.name == "input" and inp.get("type", "").lower() == "password":
                info.has_password_field = True
            form_blob.append(" ".join(str(inp.get(a, "")) for a in ("name", "id", "placeholder", "aria-label")))
            form_blob.append(inp.get_text(" ", strip=True) if inp.name == "label" else "")
        action = f.get("action", "")
        if action:
            target = urlsplit(urljoin(final_url, action))
            if target.hostname and registered_domain_of(target.hostname) != registered_domain:
                info.cross_domain_form = True
    info.asks_sensitive = bool(SENSITIVE_RE.search(" ".join(form_blob)))

    body_text = soup.get_text(" ", strip=True)[:20000]
    info.asks_payment = bool(PAYMENT_RE.search(body_text))
    info.urgency = bool(URGENCY_RE.search(body_text))
    return info


def content_findings(info: ContentInfo) -> list[Finding]:
    out: list[Finding] = []
    c = "content"
    if info.has_password_field:
        out.append(Finding("asks_password", 10, "The page asks for a password",
                           "صفحہ پاس ورڈ مانگتا ہے", c))
    if info.asks_sensitive:
        out.append(Finding("asks_sensitive", 25, "The page's form asks for sensitive details (CNIC, OTP, card or bank information)",
                           "صفحے کا فارم حساس معلومات (شناختی کارڈ، OTP، کارڈ یا بینک تفصیلات) مانگتا ہے", c))
    if info.asks_payment:
        out.append(Finding("asks_payment", 20, "The page mentions fees or mobile-wallet payments",
                           "صفحے پر فیس یا موبائل والٹ کے ذریعے ادائیگی کا ذکر ہے", c))
    if info.urgency:
        out.append(Finding("urgency", 8, "The page uses urgency wording to pressure you into acting quickly",
                           "صفحہ جلدی کرنے کے لیے دباؤ ڈالنے والے الفاظ استعمال کرتا ہے", c))
    if info.cross_domain_form:
        out.append(Finding("form_other_domain", 15, "The form sends your data to a different website",
                           "فارم آپ کا ڈیٹا کسی دوسری ویب سائٹ کو بھیجتا ہے", c))
    for org in info.org_mentions or []:
        out.append(Finding("org_mismatch_content", 15,
                           f"The page presents itself as {org['name']} but the domain is not an official one",
                           f"صفحہ خود کو {org['name']} ظاہر کرتا ہے مگر ڈومین سرکاری نہیں ہے", "official"))
    return out
