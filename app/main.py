"""FastAPI entrypoint. Exactly two endpoints: POST /analyze and GET /policy."""
import logging
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException

from app.core.detectors import normalize_for_detection, redact_pii
from app.core.gateway import analyze
from app.core.scoring import POLICY
from app.schemas import AnalyzeRequest, AnalyzeResponse, PolicyResponse

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("guardrails")

# Docs/OpenAPI routes are disabled so the app exposes exactly two endpoints.
app = FastAPI(title="GuardRail Mini", docs_url=None, redoc_url=None, openapi_url=None)


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze_endpoint(request: AnalyzeRequest) -> AnalyzeResponse:
    # 400, not 422: the shape is valid, but two documents claim the same id.
    # Same cleaning as the detectors, so look-alike letters and zero-width characters count as the same id.
    ids = [normalize_for_detection(doc.id).strip() for doc in request.context_docs]
    if len(ids) != len(set(ids)):
        raise HTTPException(status_code=400, detail="duplicate context_docs id")
    result = analyze(request)
    # Metadata only. Never log the prompt, the docs or the evidence (they may hold PII).
    logger.info(
        "time=%s request_id=%r decision=%s score=%d tags=%s docs=%d",
        datetime.now(timezone.utc).isoformat(),
        redact_pii(request.metadata.request_id)[:64],  # caller-supplied, so redact
        result.decision,
        result.risk_score,
        result.risk_tags,
        len(request.context_docs),
    )
    return result


@app.get("/policy", response_model=PolicyResponse)
def policy_endpoint() -> dict:
    return POLICY
