from typing import Literal

from pydantic import BaseModel, Field


class AnalyzeRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)
    lang: Literal["en", "ur"] = "en"


class Reason(BaseModel):
    code: str
    severity: Literal["high", "medium", "low"]
    text: str


class AnalyzeResponse(BaseModel):
    input_url: str
    final_url: str
    risk_level: Literal["low_risk", "suspicious", "high_risk"]
    score: int
    confidence: Literal["high", "medium", "low"]
    reasons: list[Reason]
    positives: list[Reason]
    recommendation: str
    explanation: str
    explanation_source: Literal["grok", "fallback"]
    signals: dict
    disclaimer: str
