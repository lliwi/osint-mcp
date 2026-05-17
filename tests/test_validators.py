import pytest

from osint_api.security.validator import (
    ValidationError,
    validate_domain,
    validate_email,
    validate_ip,
    validate_phone,
    validate_username,
    validate_url,
)


class TestValidateDomain:
    def test_valid_domains(self):
        assert validate_domain("example.com") == "example.com"
        assert validate_domain("sub.example.co.uk") == "sub.example.co.uk"
        assert validate_domain("  EXAMPLE.COM  ") == "example.com"

    def test_rejects_localhost(self):
        with pytest.raises(ValidationError):
            validate_domain("localhost")

    def test_rejects_internal_ip_like(self):
        with pytest.raises(ValidationError):
            validate_domain("192.168.1.1")  # not a valid domain, fails regex

    def test_rejects_empty(self):
        with pytest.raises(ValidationError):
            validate_domain("")

    def test_rejects_too_long(self):
        with pytest.raises(ValidationError):
            validate_domain("a" * 255 + ".com")

    def test_rejects_path_injection(self):
        with pytest.raises(ValidationError):
            validate_domain("evil.com/../../etc/passwd")


class TestValidateIP:
    def test_valid_ipv4(self):
        assert validate_ip("8.8.8.8") == "8.8.8.8"

    def test_valid_ipv6(self):
        result = validate_ip("2001:4860:4860::8888")
        assert "2001" in result

    def test_rejects_private_ipv4(self):
        with pytest.raises(ValidationError):
            validate_ip("192.168.1.1")

    def test_rejects_loopback(self):
        with pytest.raises(ValidationError):
            validate_ip("127.0.0.1")

    def test_rejects_invalid(self):
        with pytest.raises(ValidationError):
            validate_ip("not-an-ip")

    def test_rejects_command_injection(self):
        with pytest.raises(ValidationError):
            validate_ip("8.8.8.8; rm -rf /")


class TestValidateEmail:
    def test_valid_email(self):
        assert "@" in validate_email("user@example.com")

    def test_normalizes_case(self):
        result = validate_email("USER@EXAMPLE.COM")
        assert result == result.lower()

    def test_rejects_missing_at(self):
        with pytest.raises(ValidationError):
            validate_email("notanemail")

    def test_rejects_injection(self):
        with pytest.raises(ValidationError):
            validate_email("a@b\nBcc: evil@evil.com")


class TestValidateUsername:
    def test_valid_usernames(self):
        assert validate_username("alice") == "alice"
        assert validate_username("alice_bob") == "alice_bob"
        assert validate_username("alice.bob") == "alice.bob"

    def test_rejects_too_long(self):
        with pytest.raises(ValidationError):
            validate_username("a" * 65)

    def test_rejects_spaces(self):
        with pytest.raises(ValidationError):
            validate_username("alice bob")

    def test_rejects_special_chars(self):
        with pytest.raises(ValidationError):
            validate_username("alice;rm -rf /")


class TestValidateURL:
    def test_valid_http(self):
        assert validate_url("http://example.com/path") == "http://example.com/path"

    def test_valid_https(self):
        assert validate_url("https://sub.example.com/a?b=c") == "https://sub.example.com/a?b=c"

    def test_rejects_no_scheme(self):
        with pytest.raises(ValidationError):
            validate_url("example.com")

    def test_rejects_localhost(self):
        with pytest.raises(ValidationError):
            validate_url("http://localhost/secret")

    def test_rejects_internal(self):
        with pytest.raises(ValidationError):
            validate_url("http://192.168.1.1/admin")
