"""
api/schemas.py
--------------
Pydantic models = the API's "contract".

Why this matters (mentor note):
  - Pydantic validates incoming JSON for us. If a client sends a bad
    payload (missing "url", wrong type), FastAPI auto-returns a clean
    422 error *before* our code ever runs. No defensive boilerplate.
  - These models also generate the interactive API docs at /docs.
  - Defining the response shape makes the API self-documenting and
    stable — the Chrome extension can rely on these exact field names.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class PredictRequest(BaseModel):
    """The body a client POSTs to /predict."""
    url: str = Field(
        ...,                      # ... means "required"
        min_length=1,
        max_length=2048,          # browsers cap URLs near this length
        description="The URL to analyze for phishing risk.",
        examples=["http://paypal-secure-verify.login-account.tk/update"],
    )
    enrich: bool = Field(
        True,                     # ON by default for the extension's benefit
        description="Run live WHOIS/DNS lookups (Step 2). Slower (~0.3–5s) but "
                    "adds domain-age and resolution signals. Set false for a "
                    "fast, offline lexical-only check.",
    )


class PredictResponse(BaseModel):
    """The JSON we return from /predict (mirrors predict_url's dict)."""
    url: str
    label: str                    # "PHISHING" or "SAFE"
    is_phishing: bool
    confidence: float             # 0.0 - 1.0
    risk_score: int               # 0 - 100
    risk_level: str               # LOW / MEDIUM / HIGH / CRITICAL
    reasons: List[str]
    features: Dict[str, float]
    inference_ms: float
    # Present only when enrich=True. Mixed value types (ints, strings, bools,
    # None), so we type it loosely as a free-form dict.
    enrichment: Optional[Dict[str, Any]] = None


class HealthResponse(BaseModel):
    """The JSON we return from /health."""
    status: str                   # "ok"
    model_loaded: bool
    service: str
