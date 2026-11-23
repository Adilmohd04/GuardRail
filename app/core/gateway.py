"""Orchestration: run the detectors, score, decide, and build the response."""
import re
from functools import lru_cache
from typing import Callable, List, Optional

from app.core.detectors import (
    Finding,
    detect_pii,
    detect_prompt_injection,
    detect_rag_injection,
    redact_pii,
)
from app.core import intent_model
from app.core.scoring import POLICY, compute_risk_score, decide
from app.schemas import AnalyzeRequest, AnalyzeResponse, Reason, SanitizedDoc

_PLACEHOLDER = re.compile(r"\[REDACTED_\w+\]")


def _attacks(detector: Callable[[str], List[Finding]], text: str) -> List[Finding]:
    """Run an injection detector. If PII sits inside the phrase ("ignore previous 98765 43210
    instructions"), look again with the PII cut out so it cannot be used as a filler word."""
    found = detector(text)
    if found:
        return found
    redacted = redact_pii(text)
    return detector(_PLACEHOLDER.sub(" ", redacted)) if redacted != text else []


def _sanitize(text: str, attack: List[Finding], label: str) -> str:
    # If an injection was found, none of the text is passed on: the matched phrase cannot be
    # cut out exactly (typo and run-together matches have no exact span), so we drop it all.
    return f"[REMOVED: {label}]" if attack else redact_pii(text)


@lru_cache(maxsize=1)
def _model():
    return intent_model.load()  # None if the weights file is missing: the flag is then ignored


def _classify(text: str) -> Optional[Finding]:
    """Optional second opinion on text the rules allowed. Rules still win: this only adds risk."""
    model = _model()
    if model is None:
        return None
    score = model.score(text)
    if score >= intent_model.BLOCK_AT:
        return Finding("prompt_injection", f"classifier: intent resembles an instruction to the assistant (score {score:.2f})")
    if score >= model.threshold:
        return Finding("intent_classifier", f"classifier: possible instruction to the assistant, review (score {score:.2f})")
    return None


def analyze(request: AnalyzeRequest, classifier: bool = False) -> AnalyzeResponse:
    findings: List[Finding] = []
    prompt_attack = _attacks(detect_prompt_injection, request.prompt)
    findings += prompt_attack + detect_pii(request.prompt)
    verdict = _classify(request.prompt) if classifier and not prompt_attack else None
    if verdict:
        findings.append(verdict)
        if verdict.tag == "prompt_injection":
            prompt_attack = [verdict]  # same handling as a rule hit: the prompt is removed

    docs: List[SanitizedDoc] = []
    doc_attacks: List[List[Finding]] = []
    for doc in request.context_docs:
        doc_attack = _attacks(detect_rag_injection, doc.text)
        doc_attacks.append(doc_attack)
        for finding in doc_attack + detect_pii(doc.text):
            # doc.id comes from the caller, so redact it too (it could be an email).
            findings.append(Finding(finding.tag, f"{redact_pii(doc.id)}: {finding.evidence}"))
        # The id is also caller text that ends up next to the model's input, so check it too.
        id_attack = _attacks(detect_rag_injection, doc.id)
        findings += [Finding(f.tag, f"document id: {f.evidence}") for f in id_attack]
        docs.append(SanitizedDoc(
            id=_sanitize(doc.id, id_attack, "rag injection"),
            text=_sanitize(doc.text, doc_attack, "rag injection"),
        ))

    # An attack can be split over several inputs ("...ignore all previous" + "instructions..."),
    # and the model sees them together. If nothing was found alone, scan them joined.
    if request.context_docs and not prompt_attack and not any(doc_attacks):
        joined = " ".join([request.prompt] + [doc.text for doc in request.context_docs])
        split = _attacks(detect_prompt_injection, joined)
        if split:
            findings += [Finding(f.tag, f"split across inputs: {f.evidence}") for f in split]
            prompt_attack = split
            docs = [SanitizedDoc(id=d.id, text="[REMOVED: prompt injection]") for d in docs]

    found_tags = {f.tag for f in findings}
    score = compute_risk_score(found_tags)

    # Sanitized fields never carry PII or an injection, whatever the decision.
    # On "block" the caller should still not forward the content at all.
    return AnalyzeResponse(
        decision=decide(score),
        risk_score=score,
        risk_tags=[tag for tag in POLICY["detectors"] if tag in found_tags]
        + (["intent_classifier"] if "intent_classifier" in found_tags else []),
        sanitized_prompt=_sanitize(request.prompt, prompt_attack, "prompt injection"),
        sanitized_context_docs=docs,
        reasons=[Reason(tag=f.tag, evidence=f.evidence) for f in findings],
    )
