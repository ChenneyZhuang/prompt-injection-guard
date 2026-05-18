"""Prompt Injection Guard — detect prompt injection attacks in user input.

Usage:
    from guard import scan

    result = scan("What is the capital of France?")
    print(result.risk_level)  # safe
    print(result.score)       # 0.05
"""

from guard.pipeline import scan

__version__ = "0.1.0"
__all__ = ["scan"]
