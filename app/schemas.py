"""Pydantic request/response models."""
from typing import List, Literal, Optional

from pydantic import BaseModel, Field, field_validator


class ContextDoc(BaseModel):
    id: str = Field(..., min_length=1, max_length=128)
    text: str = Field(..., max_length=50_000)


class Metadata(BaseModel):
    app_id: Optional[str] = Field(None, max_length=128)
    user_id: Optional[str] = Field(None, max_length=128)
    request_id: Optional[str] = Field(None, max_length=128)


class AnalyzeRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=20_000)
    context_docs: List[ContextDoc] = Field(default_factory=list, max_length=20)
    metadata: Metadata = Field(default_factory=Metadata)

    @field_validator("prompt")
    @classmethod
    def prompt_not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("prompt must not be blank")
        return value


class SanitizedDoc(BaseModel):
    # No length limit: redaction can make text longer (a@b.co -> [REDACTED_EMAIL]).
    id: str
    text: str


class Reason(BaseModel):
    tag: str
    evidence: str


class AnalyzeResponse(BaseModel):
    decision: Literal["allow", "block", "transform"]
    risk_score: int = Field(..., ge=0, le=100)
    risk_tags: List[str]
    sanitized_prompt: str
    sanitized_context_docs: List[SanitizedDoc]
    reasons: List[Reason]


class Thresholds(BaseModel):
    block_score: int
    transform_score: int


class PolicyResponse(BaseModel):
    version: str
    detectors: List[str]
    thresholds: Thresholds
