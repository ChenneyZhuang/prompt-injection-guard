"""Configuration management — loads from env vars or .env file."""

import os
from pathlib import Path

from dotenv import load_dotenv


def _find_dotenv() -> Path | None:
    """Walk up from cwd looking for .env file."""
    cwd = Path.cwd()
    for parent in [cwd, *cwd.parents]:
        candidate = parent / ".env"
        if candidate.is_file():
            return candidate
    return None


_env_loaded = False


def load_config() -> None:
    """Load environment variables from .env file (once)."""
    global _env_loaded
    if not _env_loaded:
        dotenv_path = _find_dotenv()
        if dotenv_path:
            load_dotenv(dotenv_path)
        _env_loaded = True


def get_api_key() -> str | None:
    """Return the configured API key, or None if not set."""
    load_config()
    return os.getenv("DEEPSEEK_API_KEY") or None


def get_api_base() -> str:
    """Return the API base URL."""
    load_config()
    return os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com/v1")
