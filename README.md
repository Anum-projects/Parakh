# Parakh - AI-Powered Link Verification & Scam Detection

Verify Before You Trust. Paste a suspicious link and Parakh returns a risk level
(Low Risk / Suspicious / High Risk), the reasons, a confidence level and a plain-language
explanation, in English or Urdu.

## Structure
- `parakh-backend/` FastAPI backend (also serves the web interface)
- `parakh-backend/frontend/index.html` web interface (HTML + Tailwind + JavaScript)
- `parakh-backend/app/data/trusted_domains.json` list of official domains
- `docs/` PRD and backend guide

## Run (Windows)
Open a terminal inside `parakh-backend/`:
```
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
uvicorn app.main:app --reload --port 8000
```
If PowerShell blocks activation, first run:
`Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`

Then open http://localhost:8000. API docs: http://localhost:8000/docs

Optional: put your own `GROK_API_KEY` in `.env` (never commit or share `.env`).
Without a key the app still works with a rule-based explanation.

## Tests
`pytest` (inside `parakh-backend/` with the virtual environment active)
