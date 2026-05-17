"""
Masks PII, API keys, and secrets in tool output before returning to callers.
Tool-poisoning defense: results from the internet are data, not instructions.
"""
from __future__ import annotations

import os
import re
from typing import Any

# Patterns that look like secrets or sensitive values
_SECRET_PATTERNS = [
    re.compile(r"(?i)(password|passwd|secret|token|apikey|api_key|auth)[=:\s]+\S+"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*"),
    re.compile(r"(?i)basic\s+[A-Za-z0-9+/]+=*"),
    re.compile(r"\b[A-Fa-f0-9]{32,}\b"),  # long hex strings (hashes/keys) — keep first 8
]

# Load configured API keys from env so we can redact them explicitly
_ENV_SECRETS: list[str] = [
    v for k, v in os.environ.items()
    if k.endswith("_KEY") or k.endswith("_TOKEN") or k.endswith("_SECRET")
    if v and len(v) > 8
]


def sanitize_text(text: str) -> str:
    """Remove or mask secrets from a raw string."""
    # Redact env secrets first (exact match)
    for secret in _ENV_SECRETS:
        text = text.replace(secret, "[REDACTED]")

    # Mask pattern-based secrets
    text = _SECRET_PATTERNS[0].sub(lambda m: m.group().split("=")[0] + "=[REDACTED]", text)
    text = _SECRET_PATTERNS[1].sub("Bearer [REDACTED]", text)
    text = _SECRET_PATTERNS[2].sub("Basic [REDACTED]", text)
    # Keep first 8 chars of long hex strings to preserve partial hashes for reference
    text = _SECRET_PATTERNS[3].sub(
        lambda m: m.group()[:8] + "..." if len(m.group()) > 32 else m.group(), text
    )
    return text


def sanitize_dict(data: dict[str, Any], _depth: int = 0) -> dict[str, Any]:
    """Recursively sanitize string values in a dict."""
    if _depth > 20:
        return data
    result: dict[str, Any] = {}
    for k, v in data.items():
        if isinstance(v, str):
            result[k] = sanitize_text(v)
        elif isinstance(v, dict):
            result[k] = sanitize_dict(v, _depth + 1)
        elif isinstance(v, list):
            result[k] = sanitize_list(v, _depth + 1)
        else:
            result[k] = v
    return result


def sanitize_list(data: list[Any], _depth: int = 0) -> list[Any]:
    if _depth > 20:
        return data
    result = []
    for item in data:
        if isinstance(item, str):
            result.append(sanitize_text(item))
        elif isinstance(item, dict):
            result.append(sanitize_dict(item, _depth + 1))
        elif isinstance(item, list):
            result.append(sanitize_list(item, _depth + 1))
        else:
            result.append(item)
    return result


def mask_email(email: str) -> str:
    """Returns user@***.com style masked email."""
    if "@" not in email:
        return "***"
    local, domain = email.split("@", 1)
    parts = domain.rsplit(".", 1)
    masked_domain = "***." + parts[-1] if len(parts) > 1 else "***"
    return local[:2] + "***@" + masked_domain


def mask_phone(phone: str) -> str:
    """Returns +XX****XXXX style masked phone."""
    if len(phone) < 6:
        return "***"
    return phone[:3] + "****" + phone[-4:]
