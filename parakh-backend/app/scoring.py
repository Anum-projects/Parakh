"""Deterministic scoring. The verdict comes from rules, never from the LLM."""
from .findings import Finding

LOW_MAX, SUSPICIOUS_MAX = 30, 65

RECOMMENDATIONS = {
    "low_risk": (
        "No strong warning signs were found, but this is not a guarantee. Still avoid sharing passwords, OTPs or payment details unless you are sure of the source.",
        "کوئی نمایاں خطرے کی علامت نہیں ملی، لیکن یہ ضمانت نہیں ہے۔ جب تک ذریعے پر یقین نہ ہو، پاس ورڈ، OTP یا ادائیگی کی تفصیلات شیئر نہ کریں۔",
    ),
    "suspicious": (
        "Be careful. Verify the offer on the organization's official website or helpline before entering any personal information.",
        "احتیاط کریں۔ کوئی ذاتی معلومات درج کرنے سے پہلے ادارے کی سرکاری ویب سائٹ یا ہیلپ لائن سے تصدیق کریں۔",
    ),
    "high_risk": (
        "Avoid submitting CNIC, password, OTP, banking information or payment details until the offer is independently verified.",
        "جب تک آفر کی آزادانہ تصدیق نہ ہو جائے، شناختی کارڈ نمبر، پاس ورڈ، OTP، بینک معلومات یا ادائیگی کی تفصیلات جمع نہ کرائیں۔",
    ),
}
LOW_CONFIDENCE_NOTE = (
    " Some checks could not be completed, so please verify further.",
    " کچھ جانچیں مکمل نہیں ہو سکیں، لہٰذا مزید تصدیق کریں۔",
)
INSUFFICIENT_DATA = Finding(
    "insufficient_data", 0,
    "Not enough information could be collected to judge this link with confidence",
    "اس لنک کو اعتماد سے پرکھنے کے لیے کافی معلومات حاصل نہیں ہو سکیں", "meta")


def level_for(score: int) -> str:
    if score <= LOW_MAX:
        return "low_risk"
    if score <= SUSPICIOUS_MAX:
        return "suspicious"
    return "high_risk"


def confidence_for(checks: dict[str, bool]) -> str:
    """checks: {name: succeeded}. Only applicable checks should be included."""
    if not checks:
        return "low"
    ratio = sum(checks.values()) / len(checks)
    if ratio == 1:
        return "high"
    return "medium" if ratio >= 0.5 else "low"


def compute(findings: list[Finding], checks: dict[str, bool], official: bool, blocklisted: bool):
    """Returns (score, level, confidence, findings_used)."""
    findings = list(findings)
    score = max(0, min(100, sum(f.weight for f in findings)))
    confidence = confidence_for(checks)
    if official and not blocklisted:
        score = min(score, 10)
        confidence = "high" if confidence == "high" else "medium"
    if blocklisted:
        score = max(score, 90)
    level = level_for(score)
    if confidence == "low" and level == "low_risk":
        level = "suspicious"  # never imply certainty when data is missing
        findings.append(INSUFFICIENT_DATA)
    return score, level, confidence, findings


def recommendation(level: str, confidence: str, lang: str) -> str:
    idx = 1 if lang == "ur" else 0
    text = RECOMMENDATIONS[level][idx]
    if confidence == "low":
        text += LOW_CONFIDENCE_NOTE[idx]
    return text
