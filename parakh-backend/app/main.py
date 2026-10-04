import time
from collections import defaultdict, deque
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from .analyzers.url_analysis import InvalidURL
from .config import settings
from .pipeline import BlockedTarget, analyze
from .schemas import AnalyzeRequest, AnalyzeResponse

app = FastAPI(title="Parakh API", version="1.0.0",
              description="AI-assisted link verification and scam detection")

app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins,
                   allow_methods=["GET", "POST"], allow_headers=["Content-Type"])


class RateLimiter:
    """Simple in-memory sliding window per client IP. Use Redis if you run multiple workers."""

    def __init__(self, limit: int, window: int = 60):
        self.limit, self.window = limit, window
        self.hits: dict[str, deque] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        q = self.hits[key]
        while q and now - q[0] > self.window:
            q.popleft()
        if len(q) >= self.limit:
            return False
        q.append(now)
        return True


limiter = RateLimiter(settings.rate_limit_per_minute)


@app.get("/api/health")
async def health():
    return {"status": "ok", "grok_configured": bool(settings.grok_api_key),
            "safe_browsing_configured": bool(settings.safe_browsing_key)}


@app.post("/api/analyze", response_model=AnalyzeResponse)
async def analyze_endpoint(body: AnalyzeRequest, request: Request):
    client = request.client.host if request.client else "unknown"
    if not limiter.allow(client):
        raise HTTPException(429, "Too many requests. Please wait a minute and try again.")
    try:
        return await analyze(body.url, body.lang)
    except (InvalidURL, BlockedTarget) as e:
        raise HTTPException(400, str(e))
    except Exception:
        # Do not log the submitted URL (privacy).
        raise HTTPException(500, "The analysis failed unexpectedly. Please try again.")


FRONTEND = Path(__file__).resolve().parents[1] / "frontend"
if FRONTEND.is_dir():
    app.mount("/", StaticFiles(directory=FRONTEND, html=True), name="frontend")
