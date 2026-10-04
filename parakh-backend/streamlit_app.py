"""Parakh - Streamlit interface.

Runs the same analysis pipeline as the FastAPI backend (app/pipeline.py),
so results are identical to the HTML interface.

Run locally:   streamlit run streamlit_app.py
"""
import asyncio
import html
import sys
from pathlib import Path

import streamlit as st

# Make the `app` package importable no matter where Streamlit is started from.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.analyzers.url_analysis import InvalidURL  # noqa: E402
from app.pipeline import BlockedTarget, analyze  # noqa: E402

st.set_page_config(page_title="Parakh - Link Verification", page_icon="🔍", layout="centered")

T = {
    "en": {
        "dir": "ltr", "score": "Risk score", "conf": "Confidence",
        "reasons": "Why this link looks risky", "no_reasons": "No specific warning signs were found.",
        "positives": "Reassuring signs", "explain": "Parakh explanation", "rec": "Recommendation",
        "tech": "Technical details", "final": "Ends up at",
        "src_grok": "Explanation written by AI (Grok).",
        "src_fallback": "Explanation generated from the checks above.",
        "risk": {"low_risk": "LOW RISK", "suspicious": "SUSPICIOUS", "high_risk": "HIGH RISK"},
        "title": {"low_risk": "No Strong Warning Signs Found", "suspicious": "Caution Required",
                  "high_risk": "Multiple Warning Signs"},
        "conf_label": {"high": "High", "medium": "Medium", "low": "Low (verify further)"},
        "na": "Not available",
    },
    "ur": {
        "dir": "rtl", "score": "خطرے کا اسکور", "conf": "اعتماد کی سطح",
        "reasons": "یہ لنک خطرناک کیوں لگتا ہے", "no_reasons": "کوئی خاص انتباہی علامت نہیں ملی۔",
        "positives": "تسلی بخش علامات", "explain": "پرکھ کی وضاحت", "rec": "سفارش",
        "tech": "تکنیکی تفصیلات", "final": "آخر میں یہاں پہنچتا ہے",
        "src_grok": "وضاحت AI (Grok) نے لکھی۔", "src_fallback": "وضاحت اوپر کی جانچ سے تیار کی گئی۔",
        "risk": {"low_risk": "کم خطرہ", "suspicious": "مشکوک", "high_risk": "زیادہ خطرہ"},
        "title": {"low_risk": "کوئی واضح انتباہی علامت نہیں ملی", "suspicious": "احتیاط ضروری ہے",
                  "high_risk": "متعدد انتباہی علامات"},
        "conf_label": {"high": "زیادہ", "medium": "درمیانی", "low": "کم (مزید تصدیق کریں)"},
        "na": "دستیاب نہیں",
    },
}
RISK_COLOR = {"low_risk": "#16a34a", "suspicious": "#f59e0b", "high_risk": "#dc2626"}
SEV_COLOR = {"high": ("#fef2f2", "#991b1b"), "medium": ("#fefce8", "#854d0e"), "low": ("#f9fafb", "#374151")}


def esc(x) -> str:
    """All server text is HTML-escaped before display (links can contain hostile text)."""
    return html.escape(str(x))


def card(text: str, bg: str, fg: str, direction: str) -> None:
    st.markdown(
        f'<div dir="{direction}" style="background:{bg};color:{fg};padding:12px 14px;'
        f'border-radius:10px;margin-bottom:8px;font-size:15px">{esc(text)}</div>',
        unsafe_allow_html=True)


def show_result(d: dict, lang: str) -> None:
    t = T[lang]
    dr = t["dir"]
    level = d["risk_level"]
    color = RISK_COLOR.get(level, "#f59e0b")
    score = max(0, min(100, int(d.get("score") or 0)))

    st.markdown(
        f'<div dir="{dr}" style="background:{color};color:white;padding:18px 20px;border-radius:14px">'
        f'<div style="font-weight:700;font-size:13px;background:white;color:{color};'
        f'display:inline-block;padding:3px 12px;border-radius:999px">{esc(t["risk"].get(level, level))}</div>'
        f'<div style="font-size:24px;font-weight:700;margin-top:10px">{esc(t["title"].get(level, ""))}</div>'
        f'<div dir="ltr" style="font-size:13px;margin-top:4px;word-break:break-all">{esc(d["input_url"])}</div>'
        f'</div>', unsafe_allow_html=True)

    if d.get("final_url") and d["final_url"] != d["input_url"]:
        st.caption(f'{t["final"]}: {d["final_url"]}')

    c1, c2 = st.columns(2)
    c1.metric(t["score"], f"{score} / 100")
    c2.metric(t["conf"], t["conf_label"].get(d["confidence"], d["confidence"]))
    st.progress(score / 100)

    st.subheader(t["reasons"])
    reasons = d.get("reasons") or []
    if reasons:
        for r in reasons:
            bg, fg = SEV_COLOR.get(r.get("severity"), SEV_COLOR["low"])
            card(r["text"], bg, fg, dr)
    else:
        card(t["no_reasons"], *SEV_COLOR["low"], dr)

    if d.get("positives"):
        st.subheader(t["positives"])
        for p in d["positives"]:
            card(p["text"], "#f0fdf4", "#166534", dr)

    st.subheader(t["explain"])
    card(d["explanation"], "#eff6ff", "#1e3a8a", dr)
    st.caption(t["src_grok"] if d.get("explanation_source") == "grok" else t["src_fallback"])

    st.subheader(t["rec"])
    card(d["recommendation"], "#fffbeb", "#92400e", dr)

    with st.expander(t["tech"]):
        for k, v in (d.get("signals") or {}).items():
            st.text(f'{k.replace("_", " ")}: {t["na"] if v is None else v}')

    st.caption(d["disclaimer"])


# ---------------------------------------------------------------- page
st.title("🔍 Parakh")
st.write("**Verify Before You Trust.** Paste a suspicious scholarship, government-scheme or prize link.")

lang_name = st.radio("Result language / نتیجے کی زبان", ["English", "اردو"], horizontal=True)
lang = "ur" if lang_name == "اردو" else "en"

with st.form("check"):
    url = st.text_input("Paste link here", placeholder="https://example.com")
    submitted = st.form_submit_button("Analyze")

if submitted:
    if not url.strip():
        st.error("Please enter a link.")
    else:
        try:
            with st.spinner("Link analysis in progress... this can take up to 20 seconds."):
                result = asyncio.run(analyze(url.strip(), lang))
            show_result(result.model_dump(), lang)
        except (InvalidURL, BlockedTarget) as e:
            st.error(str(e))
        except Exception:
            st.error("The analysis failed unexpectedly. Please try again.")

st.caption("Never enter passwords, OTPs or bank details on suspicious sites. "
           "Parakh gives a risk assessment, not a guarantee.")
