"""Orchestration: run the detectors, score, decide, and build the response."""
from typing import List

from app.core.detectors import (
    Finding,
    detect_pii,
    detect_prompt_injection,
    detect_rag_injection,
    redact_pii,
)
from app.core.scoring import POLICY, compute_risk_score, decide
from app.schemas import AnalyzeRequest, AnalyzeResponse, Reason, SanitizedDoc


def analyze(request: AnalyzeRequest) -> AnalyzeResponse:
    findings: List[Finding] = []
    findings += detect_prompt_injection(request.prompt)
    findings += detect_pii(request.prompt)
    for doc in request.context_docs:
        for finding in detect_rag_injection(doc.text) + detect_pii(doc.text):
            # doc.id comes from the caller, so redact it too (it could be an email).
            findings.append(Finding(finding.tag, f"{redact_pii(doc.id)}: {finding.evidence}"))

    found_tags = {f.tag for f in findings}
    score = compute_risk_score(found_tags)

    # Sanitized fields are always PII-redacted, whatever the decision.
    # On "block" the caller should not forward the content at all.
    return AnalyzeResponse(
        decision=decide(score),
        risk_score=score,
        risk_tags=[tag for tag in POLICY["detectors"] if tag in found_tags],
        sanitized_prompt=redact_pii(request.prompt),
        sanitized_context_docs=[
            SanitizedDoc(id=redact_pii(doc.id), text=redact_pii(doc.text))
            for doc in request.context_docs
        ],
        reasons=[Reason(tag=f.tag, evidence=f.evidence) for f in findings],
    )
