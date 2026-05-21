"""
Input validation for all OSINT target types.
All user-supplied values must pass through here before any tool execution.
"""
from __future__ import annotations

import ipaddress
import os
import re
import unicodedata

try:
    import phonenumbers
    _HAS_PHONENUMBERS = True
except ImportError:
    _HAS_PHONENUMBERS = False

try:
    from email_validator import validate_email as _validate_email_lib, EmailNotValidError
    _HAS_EMAIL_VALIDATOR = True
except ImportError:
    _HAS_EMAIL_VALIDATOR = False

# RFC-compliant domain regex (labels 1-63 chars, total ≤253)
_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}$"
)

_USERNAME_RE = re.compile(r"^[a-zA-Z0-9._\-]{1,64}$")

_CRYPTO_WALLET_RE = re.compile(r"^[a-zA-Z0-9]{20,100}$")

# Safe relative file path — no .. or absolute paths
_SAFE_FILENAME_RE = re.compile(r"^[a-zA-Z0-9._\-]{1,200}$")


class ValidationError(ValueError):
    pass


def validate_domain(value: str) -> str:
    value = value.strip().lower()
    # Normalize unicode to NFKC then reject non-ASCII
    value = unicodedata.normalize("NFKC", value)
    if not value or len(value) > 253:
        raise ValidationError(f"Invalid domain: '{value}'")
    if not _DOMAIN_RE.match(value):
        raise ValidationError(f"Invalid domain format: '{value}'")
    # Block private / internal targets
    _block_internal_hostname(value)
    return value


def validate_ip(value: str) -> str:
    value = value.strip()
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        raise ValidationError(f"Invalid IP address: '{value}'")
    if addr.is_private or addr.is_loopback or addr.is_link_local:
        raise ValidationError(f"Private/reserved IP addresses are not allowed: '{value}'")
    return str(addr)


def validate_email(value: str) -> str:
    value = value.strip().lower()
    if _HAS_EMAIL_VALIDATOR:
        try:
            info = _validate_email_lib(value, check_deliverability=False)
            return info.normalized
        except EmailNotValidError as exc:
            raise ValidationError(f"Invalid email: {exc}") from exc
    # Fallback: basic regex
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", value):
        raise ValidationError(f"Invalid email format: '{value}'")
    return value


def validate_phone(value: str) -> str:
    value = value.strip()
    if _HAS_PHONENUMBERS:
        try:
            parsed = phonenumbers.parse(value, None)
            if not phonenumbers.is_valid_number(parsed):
                raise ValidationError(f"Invalid phone number: '{value}'")
            return phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
        except phonenumbers.NumberParseException as exc:
            raise ValidationError(f"Cannot parse phone number '{value}': {exc}") from exc
    # Fallback: accept E.164-like strings
    if not re.match(r"^\+?[1-9]\d{6,14}$", value):
        raise ValidationError(f"Invalid phone number format: '{value}'")
    return value


def validate_username(value: str) -> str:
    value = value.strip()
    if not _USERNAME_RE.match(value):
        raise ValidationError(
            f"Invalid username '{value}': only alphanumeric, dots, underscores and hyphens allowed (1-64 chars)"
        )
    return value


def validate_url(value: str) -> str:
    value = value.strip()
    if not re.match(r"^https?://[^\s]{4,2000}$", value, re.IGNORECASE):
        raise ValidationError(f"Invalid URL: '{value}'")
    # Must not point at internal hosts
    host_match = re.match(r"^https?://([^/:?#]+)", value, re.IGNORECASE)
    if host_match:
        host = host_match.group(1).lower()
        _block_internal_hostname(host)
    return value


def validate_file_path(value: str, base_dir: str) -> str:
    """Validates that value is a safe filename inside base_dir."""
    basename = os.path.basename(value)
    if not _SAFE_FILENAME_RE.match(basename):
        raise ValidationError(f"Unsafe filename: '{basename}'")
    resolved = os.path.realpath(os.path.join(base_dir, basename))
    if not resolved.startswith(os.path.realpath(base_dir)):
        raise ValidationError("Path traversal detected")
    return resolved


def validate_wallet(value: str) -> str:
    value = value.strip()
    if not _CRYPTO_WALLET_RE.match(value):
        raise ValidationError(f"Invalid wallet address: '{value}'")
    return value


def validate_license_plate(value: str, country: str = "ES") -> str:
    """
    Validates and normalises a Spanish license plate or VIN.
    Returns uppercase normalised value without separators.
    """
    value = value.strip().upper().replace("-", "").replace(" ", "").replace(".", "")

    # VIN (17 chars, used internationally)
    _VIN = re.compile(r"^[A-HJ-NPR-Z0-9]{17}$")
    if _VIN.match(value):
        return value

    # Modern Spain (since 2000): 4 digits + 3 letters (all consonants accepted here;
    # the API validates the actual format)
    _ES_MODERN = re.compile(r"^\d{4}[A-Z]{3}$")
    # Old provincial: 1-2 letters + 4 digits + 2 letters
    _ES_OLD = re.compile(r"^[A-Z]{1,2}\d{4}[A-Z]{2}$")

    if _ES_MODERN.match(value) or _ES_OLD.match(value):
        return value

    raise ValidationError(
        f"Formato no reconocido: '{value}'. "
        "Usa una matrícula española (ej. 1234ABC, M1234AB) o un VIN de 17 caracteres."
    )


def validate_hash(value: str) -> str:
    value = value.strip().lower()
    if not re.match(r"^[a-f0-9]{32,128}$", value):
        raise ValidationError(f"Invalid hash value: '{value}'")
    return value


# ─── Internal helpers ────────────────────────────────────────────────────────

_BLOCKED_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}
_INTERNAL_PREFIXES = ("192.168.", "10.", "172.16.", "172.17.", "172.18.",
                       "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
                       "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
                       "172.29.", "172.30.", "172.31.")


def _block_internal_hostname(host: str) -> None:
    if host in _BLOCKED_HOSTS:
        raise ValidationError(f"Internal/loopback host not allowed: '{host}'")
    for prefix in _INTERNAL_PREFIXES:
        if host.startswith(prefix):
            raise ValidationError(f"Internal network host not allowed: '{host}'")
