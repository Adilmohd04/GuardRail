"""Pydantic request/response models."""
from typing import List, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from app.core.detectors import strip_invisible

MAX_TOTAL_DOC_CHARS = 200_000  # all documents together; keeps the worst-case request fast


class ContextDoc(BaseModel):
    id: str = Field(..., min_length=1, max_length=128)
    text: str = Field(..., max_length=50_000)

    @field_validator("id")
    @classmethod
    def id_not_blank(cls, value: str) -> str:
        if not strip_invisible(value).strip():
            raise ValueError("id must not be blank")
        return value


class Metadata(BaseModel):
    # All three are required (a missing or blank one gives 422), so every request can be traced.
    app_id: str = Field(..., min_length=1, max_length=128)
    user_id: str = Field(..., min_length=1, max_length=128)
    request_id: str = Field(..., min_length=1, max_length=128)

    @field_validator("app_id", "user_id", "request_id")
    @classmethod
    def not_blank(cls, value: str) -> str:
        if not strip_invisible(value).strip():  # zero-width characters are not content
            raise ValueError("must not be blank")
        return value


class AnalyzeRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=20_000)
    context_docs: List[ContextDoc] = Field(default_factory=list, max_length=20)
    metadata: Metadata

    @field_validator("prompt")
    @classmethod
    def prompt_not_blank(cls, value: str) -> str:
        if not strip_invisible(value).strip():
            raise ValueError("prompt must not be blank")
        return value

    @model_validator(mode="after")
    def documents_not_too_large(self):
        if sum(len(doc.text) for doc in self.context_docs) > MAX_TOTAL_DOC_CHARS:
            raise ValueError(f"context_docs together must be at most {MAX_TOTAL_DOC_CHARS} characters")
        return self


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
