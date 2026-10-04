# Parakh Backend (FastAPI)

Link verification and scam detection API. Returns Low Risk / Suspicious / High Risk with reasons, confidence and a plain-language explanation (Grok, with a rule-based fallback).

## Run
```
python -m venv .venv
.venv\Scripts\activate          (Mac/Linux: source .venv/bin/activate)
pip install -r requirements.txt
copy .env.example .env          (Mac/Linux: cp .env.example .env)
uvicorn app.main:app --reload --port 8000
```
Edit `.env` to add `GROK_API_KEY` (optional; without it a rule-based explanation is used). Never commit `.env`.

Docs (try the API in the browser): http://localhost:8000/docs
Health check: http://localhost:8000/api/health

## API
`POST /api/analyze`

Request:
```json
{ "url": "https://example-scholarship.xyz/register", "lang": "en" }
```
`lang` is `en` or `ur`.

Response fields: `input_url`, `final_url`, `risk_level` (`low_risk` | `suspicious` | `high_risk`), `score` (0-100), `confidence` (`high` | `medium` | `low`), `reasons[]` and `positives[]` (each has `code`, `severity`, `text`), `recommendation`, `explanation`, `explanation_source` (`grok` | `fallback`), `signals{}`, `disclaimer`.

Errors: 400 invalid or private URL, 429 too many requests, 500 unexpected failure.

## Frontend teammates
Call the endpoint above with `fetch`. If your frontend runs on another address (e.g. `http://localhost:3000` or `http://localhost:5500`), add it to `CORS_ORIGINS` in `.env`, then restart the server.

## Tests
```
pytest
```

## Structure
```
app/main.py                  API, rate limit, CORS
app/pipeline.py              runs all checks for one URL
app/scoring.py               weighted score, thresholds, confidence
app/llm.py                   Grok explanation + fallback
app/analyzers/url_analysis.py      URL structure rules
app/analyzers/domain_analysis.py   DNS, WHOIS age, SSL
app/analyzers/fetch.py             safe redirect following (SSRF protected)
app/analyzers/content_analysis.py  forms, sensitive-data and payment wording
app/analyzers/official_sources.py  trusted-domain matching
app/analyzers/reputation.py        Google Safe Browsing (optional)
app/data/trusted_domains.json      starter list of official domains (verify and extend)
```

## Streamlit interface (optional)
Same analysis, Streamlit front end:
```
pip install -r requirements.txt
streamlit run streamlit_app.py
```
Streamlit Community Cloud: main file path `parakh-backend/streamlit_app.py`.
Add `GROK_API_KEY = "..."` under Advanced settings, Secrets (optional).
