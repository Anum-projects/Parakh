import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
    grok_api_key: str = os.getenv("GROK_API_KEY", "")
    grok_base_url: str = os.getenv("GROK_BASE_URL", "https://api.x.ai/v1").rstrip("/")
    grok_model: str = os.getenv("GROK_MODEL", "grok-4")
    safe_browsing_key: str = os.getenv("SAFE_BROWSING_API_KEY", "")
    cors_origins: list[str] = [
        o.strip() for o in os.getenv("CORS_ORIGINS", "http://localhost:8000").split(",") if o.strip()
    ]
    rate_limit_per_minute: int = int(os.getenv("RATE_LIMIT_PER_MINUTE", "20"))


settings = Settings()
