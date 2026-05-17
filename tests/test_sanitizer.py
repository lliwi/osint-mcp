from osint_api.security.sanitizer import mask_email, mask_phone, sanitize_text


class TestSanitizeText:
    def test_removes_password_patterns(self):
        result = sanitize_text("password=supersecret123")
        assert "supersecret123" not in result
        assert "REDACTED" in result

    def test_removes_bearer_tokens(self):
        result = sanitize_text("Authorization: Bearer abc123xyz456")
        assert "abc123xyz456" not in result
        assert "REDACTED" in result

    def test_passes_benign_text(self):
        result = sanitize_text("The domain was registered in 2020")
        assert result == "The domain was registered in 2020"


class TestMaskEmail:
    def test_masks_email(self):
        masked = mask_email("user@example.com")
        assert "@" in masked
        assert "***" in masked
        assert "user@example.com" != masked

    def test_handles_no_at(self):
        result = mask_email("notanemail")
        assert result == "***"


class TestMaskPhone:
    def test_masks_phone(self):
        masked = mask_phone("+34123456789")
        assert "****" in masked
        assert "+34123456789" != masked

    def test_short_phone(self):
        result = mask_phone("123")
        assert result == "***"
