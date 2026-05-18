# Prompt Injection Guard — Skill

## Overview

**Prompt Injection Guard** is a dual-mode (LLM + regex) prompt injection detection system. It analyses user input for injection attack patterns and returns structured results with risk scores, reasoning, and safe alternatives.

## Quick Links

- **Repository:** https://github.com/ChenneyZhuang/prompt-injection-guard
- **Installation:** `pip install -e .` from repo root
- **Python:** 3.11+
- **License:** MIT

## When to Use This Skill

Use this skill when the user asks about:

- Detecting prompt injection in user input
- Security scanning for LLM applications
- Understanding attack vectors (ignore instructions, role manipulation, jailbreaks, prompt leaking, code injection, etc.)
- Setting up or configuring prompt injection detection
- Adding safety layers to AI pipelines
- Understanding how the regex patterns or LLM-based detection work

## Core Architecture

```text
User Input → pipeline.scan()
  ├─ API key set? → DeepSeek LLM (async httpx)
  └─ No key / error → Regex pattern matcher (20+ rules)
```

### Key Components

| Component | File | Purpose |
|-----------|------|---------|
| Public API | `src/guard/__init__.py` | `from guard import scan` |
| Pipeline | `src/guard/pipeline.py` | Orchestrates LLM → regex fallback |
| CLI | `src/guard/cli.py` | `guard "text"` command, JSON/rich output |
| Config | `src/guard/config.py` | `.env` loading, `DEEPSEEK_API_KEY` |
| Schemas | `src/guard/models/schemas.py` | `ScanResult`, `RiskLevel`, `PatternMatch` |
| Scanner | `src/guard/agents/scanner.py` | DeepSeek API client |
| Patterns | `src/guard/tools/patterns.py` | 20+ regex rules + compounding scorer |
| Tests | `src/guard/tests/test_patterns.py` | Detection + false-positive tests |

### ScanResult Model

```python
class ScanResult(BaseModel):
    input_text: str          # Original input
    score: float             # 0.0 (safe) to 1.0 (critical)
    risk_level: RiskLevel    # safe | low | medium | high | critical
    is_injection: bool       # True when score >= 0.5
    reasoning: str           # Human-readable explanation
    patterns_matched: list[PatternMatch]  # Which regex rules fired
    safe_alternative: str | None  # Suggested rephrase
    method: str              # "llm" or "regex"
```

### Risk Level Mapping

| Level | Score Range | Action |
|-------|-------------|--------|
| safe | 0.00–0.19 | Pass through |
| low | 0.20–0.49 | Log, allow, monitor |
| medium | 0.50–0.69 | Strip or quarantine |
| high | 0.70–0.89 | Block and alert |
| critical | 0.90–1.00 | Block, alert, audit |

### Regex Pattern Categories (20+)

The pattern engine uses a non-linear compounding formula: `score = 1 - ∏(1 - w_i)`.

**High-weight patterns (0.30–0.40):**
- `system_override` — "Ignore all previous instructions..."
- `new_system_prompt` — "System prompt is now:..."
- `you_are_dan` — DAN/Developer Mode jailbreaks
- `prompt_leak` — "Repeat your instructions..."
- `delimiter_override` — "Respond without safety guidelines..."
- `special_token_abuse` — `<|im_start|>`, `<|im_end|>`

**Medium-weight patterns (0.20–0.30):**
- `act_as` — "You are now / Act as..."
- `role_switch`, `authority_claim`, `urgent_override`
- `completion_hijack`, `delimiter_injection`
- `translation_attack`, `code_injection`, `context_poisoning`
- `token_leak`

**Low-weight patterns (0.12–0.20):**
- `sql_injection`, `base64_blob`, `repetition_attack`

## Usage Patterns

### Python Library (sync)
```python
from guard import scan
result = scan("What is the capital of France?")
# result.risk_level -> RiskLevel.SAFE
# result.score -> 0.0
```

### Python Library (async)
```python
from guard import scan_async
result = await scan_async("Ignore previous instructions")
```

### CLI
```bash
guard "some text"
echo "some text" | guard
guard --json "some text"
guard -v "text"  # verbose logging
```

### Exit Codes
- `0` = safe/low/medium
- `1` = high/critical (or error)

## Configuration

- `DEEPSEEK_API_KEY` — Enable LLM mode
- `DEEPSEEK_BASE_URL` — Custom API endpoint (default: DeepSeek official)
- Copy `.env.example` → `.env` to configure

## Adding New Patterns

Edit `src/guard/tools/patterns.py` → `RULES` list:

```python
_Rule(
    "my_pattern_name",
    r"(?i)regex with capture groups",
    "Human description of what this detects",
    0.25,  # weight contribution
)
```

## Testing

```bash
pytest src/guard/tests/ -v
pytest src/guard/tests/ --cov=guard --cov-report=html
```

## Key Design Decisions

1. **Zero-config fallback** — Works immediately without API keys using regex
2. **Non-linear scoring** — Multiple medium matches compound to high/critical
3. **LLM as optional enhancement** — Better semantic understanding when available
4. **Pydantic throughout** — Type-safe, serialisable results
5. **Explainable** — Every result includes human-readable reasoning
6. **False-positive conscious** — Tests explicitly verify safe inputs don't trigger
