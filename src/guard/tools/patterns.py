"""Regex-based pattern matching engine for prompt injection detection.

This is the fallback when no LLM API key is configured.
Uses a curated set of regex patterns covering the most common
prompt injection attack vectors.
"""

from __future__ import annotations

import re
from typing import NamedTuple

from guard.models.schemas import PatternMatch, RiskLevel


class _Rule(NamedTuple):
    """Internal rule: (category_name, regex_pattern, description, weight)."""

    name: str
    pattern: str
    description: str
    weight: float  # Contribution to the final score if matched


# ── Curated pattern library ──────────────────────────────────────────────────
# Each rule has a weight. Multiple matches compound toward a higher score.

RULES: list[_Rule] = [
    # === Direct overrides (very high severity) ===
    _Rule(
        "system_override",
        r"(?i)(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|messages?|directives?)",
        "Instructs the model to ignore previous instructions",
        0.35,
    ),
    _Rule(
        "system_override_variant",
        r"(?i)(you\s+are\s+now|act\s+as|pretend\s+(you\s+are|to\s+be)|role[- ]?play\s+as)\s+.{3,80}",
        "Attempts to redefine the model's role or persona",
        0.30,
    ),
    _Rule(
        "new_system_prompt",
        r"(?i)(system\s*(prompt|message|instruction|directive)\s*(is\s*now|:)|new\s+system\s+(prompt|instruction))",
        "Attempts to inject a new system prompt",
        0.40,
    ),
    _Rule(
        "you_are_dan",
        r"(?i)\b(DAN|do\s+anything\s+now|developer\s*mode)\b",
        "DAN / Developer Mode jailbreak attempt",
        0.30,
    ),
    _Rule(
        "delimiter_override",
        r"(?i)(output|respond|reply)\s+(without|ignoring?|skipping?)\s+(any|the|your)?\s*(ethical|safety|content|guidelines?|restrictions?|rules?)",
        "Instructs the model to bypass safety filters",
        0.35,
    ),
    # === Role manipulation ===
    _Rule(
        "role_switch",
        r"(?i)(from\s+now\s+on\s+(you\s+are|your\s+role\s+is)|assume\s+the\s+role\s+of|take\s+on\s+the\s+persona\s+of)",
        "Attempts to permanently switch the model's role",
        0.25,
    ),
    _Rule(
        "authority_claim",
        r"(?i)(I\s+(am|have)\s+(the\s+)?(admin|administrator|developer|creator|owner|root|superuser))",
        "User claims authority to override system behaviour",
        0.25,
    ),
    _Rule(
        "urgent_override",
        r"(?i)(URGENT|EMERGENCY|CRITICAL)\s*:\s*(override|bypass|ignore|disable)",
        "Uses urgency to demand security override",
        0.28,
    ),
    # === Payload / code injection ===
    _Rule(
        "code_injection",
        r"(?i)(```|<script>|<\?php|eval\s*\(|exec\s*\(|system\s*\(|os\.system|subprocess\.)",
        "Contains executable code or script tags",
        0.20,
    ),
    _Rule(
        "sql_injection",
        r"(?i)(select\s+.*\s+from\s+|drop\s+table|union\s+select|1\s*=\s*1|'\s*OR\s+'1'\s*=\s*'1)",
        "Classic SQL injection patterns",
        0.15,
    ),
    # === Prompt leaking ===
    _Rule(
        "prompt_leak",
        r"(?i)(reveal|repeat|echo|print|output|display|show|tell\s+me)\s+(your\s+)?(system\s+)?(prompt|instructions?|rules?|initial|setup|config(uration)?)\b",
        "Attempts to extract the system prompt",
        0.32,
    ),
    _Rule(
        "token_leak",
        r"(?i)(what\s+(is|are)\s+your\s+(API\s+)?(key|token|secret|credential|password))",
        "Attempts to extract secrets or credentials",
        0.20,
    ),
    # === Translation / encoding attacks ===
    _Rule(
        "translation_attack",
        r"(?i)(translate|decipher|decode)\s+(the\s+(following|above|below)|this)\s+(into|to|from)\s+(base64|hex|binary|morse|rot13)",
        "Uses translation as a vector to hide malicious content",
        0.22,
    ),
    _Rule(
        "base64_blob",
        r"(?i)[A-Za-z0-9+/]{40,}={0,2}",
        "Long base64-encoded string (potential hidden payload)",
        0.18,
    ),
    # === Boundary / completion attacks ===
    _Rule(
        "completion_hijack",
        r"(?i)(start\s+(your|the)\s+(response|reply|output|answer)\s+with\s+|begin\s+(your|the)\s+(output|reply)\s+with\s+)",
        "Forces the model to start its response with attacker-chosen text",
        0.28,
    ),
    _Rule(
        "delimiter_injection",
        r"(?i)(\n\s*(user|assistant|system|human|ai)\s*:[\s\S]*?(?=\n\s*(user|assistant|system|human|ai)\s*:|$))",
        "Injects fake conversation turns using delimiter tokens",
        0.26,
    ),
    # === Multi-turn / context poisoning ===
    _Rule(
        "context_poisoning",
        r"(?i)(false|fake|misleading|incorrect).{0,30}(information|data|fact).{0,30}(believ|accept|assume)",
        "Attempts to make the model accept false premises",
        0.20,
    ),
    # === DoS / resource exhaustion ===
    _Rule(
        "repetition_attack",
        r"(.{10,})\1{4,}",
        "Highly repetitive text (potential DoS or pattern-attack)",
        0.12,
    ),
    # === Token smuggling ===
    _Rule(
        "special_token_abuse",
        r"(?i)(<\|im_start\|>|<\|im_end\|>|<\|endoftext\|>|</?\|?assistant\|?>)",
        "Uses special tokens to manipulate conversation structure",
        0.30,
    ),
]


def scan_patterns(text: str) -> list[PatternMatch]:
    """Scan *text* against all known injection patterns.

    Args:
        text: The user input to scan.

    Returns:
        List of PatternMatch objects for every rule that matched.
    """
    matches: list[PatternMatch] = []
    for rule in RULES:
        for m in re.finditer(rule.pattern, text, re.IGNORECASE | re.DOTALL):
            matches.append(
                PatternMatch(
                    name=rule.name,
                    pattern=rule.pattern,
                    matched_text=m.group(0).strip(),
                    description=rule.description,
                )
            )
    return matches


def compute_score(matches: list[PatternMatch]) -> float:
    """Compute aggregate risk score from matched patterns.

    Uses a non-linear compounding formula so that multiple medium matches
    push the score higher than one critical match alone.

    Args:
        matches: List of pattern matches from ``scan_patterns``.

    Returns:
        Float between 0.0 and 1.0.
    """
    if not matches:
        return 0.0

    # Look up weights by name (first match per rule category counts)
    name_to_weight: dict[str, float] = {}
    for rule in RULES:
        name_to_weight[rule.name] = rule.weight

    seen: set[str] = set()
    weights: list[float] = []
    for m in matches:
        if m.name not in seen:
            seen.add(m.name)
            weights.append(name_to_weight.get(m.name, 0.1))

    # Compound formula: 1 - ∏(1 - w_i)  →  asymptotically approaches 1.0
    product = 1.0
    for w in weights:
        product *= 1.0 - w
    score = 1.0 - product

    return round(min(score, 1.0), 4)


def score_to_level(score: float) -> RiskLevel:
    """Map a numeric score to a RiskLevel."""
    if score >= 0.9:
        return RiskLevel.CRITICAL
    if score >= 0.7:
        return RiskLevel.HIGH
    if score >= 0.5:
        return RiskLevel.MEDIUM
    if score >= 0.2:
        return RiskLevel.LOW
    return RiskLevel.SAFE
