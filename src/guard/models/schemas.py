"""Pydantic models for scan results and risk levels."""

from enum import StrEnum

from pydantic import BaseModel, Field


class RiskLevel(StrEnum):
    """Risk level assigned to a scan result."""

    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PatternMatch(BaseModel):
    """A single regex pattern that matched the input."""

    name: str = Field(description="Human-readable name of the matched pattern category")
    pattern: str = Field(description="The regex pattern that triggered")
    matched_text: str = Field(description="The actual text fragment that matched", default="")
    description: str = Field(description="Explanation of what this pattern detects", default="")


class ScanResult(BaseModel):
    """Complete result of a prompt injection scan."""

    input_text: str = Field(description="The original input text that was scanned")
    score: float = Field(
        description="Risk score from 0.0 (safe) to 1.0 (critical)",
        ge=0.0,
        le=1.0,
    )
    risk_level: RiskLevel = Field(description="Categorised risk level")
    is_injection: bool = Field(description="Whether injection was detected (score >= 0.5)")
    reasoning: str = Field(description="Explanation of why this score/level was assigned")
    patterns_matched: list[PatternMatch] = Field(
        default_factory=list,
        description="Regex patterns that matched (empty when LLM-only)",
    )
    safe_alternative: str | None = Field(
        default=None,
        description="Suggested safe rephrasing of the input, if applicable",
    )
    method: str = Field(
        default="regex",
        description="Detection method used: 'llm' or 'regex'",
    )
