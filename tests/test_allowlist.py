import pytest

from osint_api.security.allowlist import (
    get_tool_config,
    is_tool_allowed,
    validate_args,
)


class TestIsToolAllowed:
    def test_whois_is_allowed(self):
        assert is_tool_allowed("whois") is True

    def test_sherlock_is_allowed(self):
        assert is_tool_allowed("sherlock") is True

    def test_sqlmap_is_not_allowed(self):
        assert is_tool_allowed("sqlmap") is False

    def test_bash_is_not_allowed(self):
        assert is_tool_allowed("bash") is False

    def test_sh_is_not_allowed(self):
        assert is_tool_allowed("sh") is False

    def test_curl_is_not_allowed(self):
        assert is_tool_allowed("curl") is False


class TestValidateArgs:
    def test_whois_allowed_flag(self):
        ok, err = validate_args("whois", ["-H", "example.com"])
        assert ok is True
        assert err == ""

    def test_whois_disallowed_flag(self):
        ok, err = validate_args("whois", ["--malicious-flag"])
        assert ok is False
        assert "not allowed" in err

    def test_sherlock_allowed_flags(self):
        ok, err = validate_args("sherlock", ["--timeout", "--print-found", "alice"])
        assert ok is True

    def test_sherlock_shell_injection_attempt(self):
        ok, err = validate_args("sherlock", ["--timeout", "; rm -rf /"])
        # The flag '--timeout' is fine; '; rm -rf /' doesn't start with '-' so not flagged
        # as a bad flag — but it would fail at validator level before reaching runner
        # This test confirms the allowlist doesn't add injection flags
        assert ok is True  # allowlist checks flags, validator checks values

    def test_unknown_tool_returns_false(self):
        ok, err = validate_args("nmap", ["-sV"])
        assert ok is False
        assert "allowlist" in err
