"""FastAPI entrypoint. Exactly two endpoints: POST /analyze and GET /policy."""
import logging
from datetime import datetime, timezone

from fastapi import FastAPI

from app.core.gateway import analyze
from app.core.scoring import POLICY
from app.schemas import AnalyzeRequest, AnalyzeResponse, PolicyResponse

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("guardrails")

# Docs/OpenAPI routes are disabled so the app exposes exactly two endpoints.
app = FastAPI(title="GuardRail Mini", docs_url=None, redoc_url=None, openapi_url=None)


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze_endpoint(request: AnalyzeRequest) -> AnalyzeResponse:
    result = analyze(request)
    # Metadata only. Never log the prompt, the docs or the evidence (they may hold PII).
    logger.info(
        "time=%s request_id=%r decision=%s score=%d tags=%s docs=%d",
        datetime.now(timezone.utc).isoformat(),
        (request.metadata.request_id or "")[:64],
        result.decision,
        result.risk_score,
        result.risk_tags,
        len(request.context_docs),
    )
    return result


@app.get("/policy", response_model=PolicyResponse)
def policy_endpoint() -> dict:
    return POLICY
