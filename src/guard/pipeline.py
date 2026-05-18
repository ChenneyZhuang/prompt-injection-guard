"""Pipeline — orchestrates the full detection workflow.

Tries LLM first (if API key is available), falls back to regex pattern matching.
"""

from __future__ import annotations

import asyncio
import logging

from guard.config import get_api_base, get_api_key
from guard.models.schemas import RiskLevel, ScanResult
from guard.tools.patterns import compute_score, scan_patterns, score_to_level

logger = logging.getLogger(__name__)


async def _llm_scan(text: str) -> ScanResult:
    """Run LLM-based detection and wrap in a ScanResult."""
    api_key = get_api_key()
    if not api_key:
        raise ValueError("No API key configured — cannot use LLM scanner")

    from guard.agents.scanner import scan_with_llm

    result = await scan_with_llm(text, api_key, get_api_base())

    score = float(result["score"])
    # Clamp
    score = max(0.0, min(1.0, score))

    try:
        risk_level = RiskLevel(result["risk_level"].lower())
    except ValueError:
        risk_level = score_to_level(score)

    return ScanResult(
        input_text=text,
        score=score,
        risk_level=risk_level,
        is_injection=score >= 0.5,
        reasoning=result["reasoning"],
        patterns_matched=[],
        safe_alternative=result.get("safe_alternative"),
        method="llm",
    )


def _regex_scan(text: str) -> ScanResult:
    """Run regex pattern matching and wrap in a ScanResult."""
    matches = scan_patterns(text)
    score = compute_score(matches)
    risk_level = score_to_level(score)

    if matches:
        match_descriptions = "; ".join(f"{m.name}: {m.description}" for m in matches[:5])
        reasoning = f"Matched {len(matches)} pattern(s): {match_descriptions}"
    else:
        reasoning = "No injection patterns detected in the input."

    # Only suggest safe alternative for injection-like inputs
    safe_alternative = None
    if score >= 0.5:
        safe_alternative = _generate_safe_alternative(text, matches)

    return ScanResult(
        input_text=text,
        score=score,
        risk_level=risk_level,
        is_injection=score >= 0.5,
        reasoning=reasoning,
        patterns_matched=matches,
        safe_alternative=safe_alternative,
        method="regex",
    )


def _generate_safe_alternative(text: str, matches: list) -> str | None:
    """Suggest a safe rephrasing by stripping detected patterns."""
    # Simple heuristic: if the user is asking something legitimate but
    # embedded in injection language, suggest stripping the injection bits.
    if not matches:
        return None

    cleaned = text
    for m in matches:
        cleaned = cleaned.replace(m.matched_text, "[removed]")

    # Squash multiple spaces
    import re

    cleaned = re.sub(r"\s+", " ", cleaned).strip()

    if cleaned and cleaned != text:
        return cleaned
    return "Please rephrase your request without attempting to override system instructions."


def scan(text: str) -> ScanResult:
    """Scan *text* for prompt injection attacks.

    Uses LLM-based detection if a ``DEEPSEEK_API_KEY`` is configured;
    otherwise falls back to regex pattern matching.

    Args:
        text: The user input string to analyse.

    Returns:
        A ``ScanResult`` with score, risk level, reasoning, and any
        matched patterns.

    Example:
        >>> from guard import scan
        >>> result = scan("What is the capital of France?")
        >>> result.risk_level
        <RiskLevel.SAFE: 'safe'>
    """
    api_key = get_api_key()

    if api_key:
        logger.info("Using LLM-based detection (DeepSeek API)")
        try:
            return asyncio.run(_llm_scan(text))
        except Exception:
            logger.warning("LLM scan failed, falling back to regex", exc_info=True)

    logger.info("Using regex pattern matching")
    return _regex_scan(text)


async def scan_async(text: str) -> ScanResult:
    """Async version of :func:`scan`. Always tries LLM first if key is set."""
    api_key = get_api_key()

    if api_key:
        logger.info("Using LLM-based detection (DeepSeek API)")
        try:
            return await _llm_scan(text)
        except Exception:
            logger.warning("LLM scan failed, falling back to regex", exc_info=True)

    logger.info("Using regex pattern matching")
    return _regex_scan(text)
