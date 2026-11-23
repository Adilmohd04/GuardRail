"""Policy and scoring. This file is the single source of truth: GET /policy serves POLICY."""
from typing import Iterable

POLICY = {
    "version": "1",
    "detectors": ["prompt_injection", "pii", "rag_injection"],
    "thresholds": {"block_score": 80, "transform_score": 40},
}

# One fixed score per risk category. Not a probability, just a policy choice.
# "intent_classifier" is only used when a request asks for the optional classifier.
RISK_SCORES = {"pii": 40, "prompt_injection": 80, "rag_injection": 80, "intent_classifier": 40}


def compute_risk_score(tags: Iterable[str]) -> int:
    """Sum the score of each UNIQUE category (repeat matches add nothing), capped at 100."""
    return min(100, sum(RISK_SCORES[tag] for tag in set(tags)))


def decide(score: int) -> str:
    if score >= POLICY["thresholds"]["block_score"]:
        return "block"
    if score >= POLICY["thresholds"]["transform_score"]:
        return "transform"
    return "allow"
