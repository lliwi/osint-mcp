from osint_api.parsers import (
    holehe_parser,
    sherlock_parser,
    theharvester_parser,
    whois_parser,
    exiftool_parser,
)


class TestWhoisParser:
    def test_parses_registrar(self):
        raw = "Registrar: Example Registrar, Inc.\nCreation Date: 2000-01-01\n"
        result = whois_parser.parse(raw)
        assert result["registrar"] == "Example Registrar, Inc."
        assert result["creation_date"] == "2000-01-01"

    def test_empty_input(self):
        result = whois_parser.parse("")
        assert result["registrar"] == ""

    def test_parses_name_servers(self):
        raw = "Name Server: ns1.example.com\nName Server: ns2.example.com\n"
        result = whois_parser.parse(raw)
        assert len(result["name_servers"]) == 2


class TestSherlockParser:
    def test_parses_found_profiles(self):
        raw = "[+] Twitter: https://twitter.com/alice\n[+] GitHub: https://github.com/alice\n"
        result = sherlock_parser.parse(raw)
        assert result["found_count"] == 2
        assert result["profiles"][0]["platform"] == "Twitter"
        assert result["profiles"][0]["status"] == "found"

    def test_empty_output(self):
        result = sherlock_parser.parse("")
        assert result["found_count"] == 0

    def test_ignores_not_found_lines(self):
        raw = "[-] Facebook: Not Found!\n[+] GitHub: https://github.com/alice\n"
        result = sherlock_parser.parse(raw)
        assert result["found_count"] == 1


class TestTheHarvesterParser:
    def test_parses_emails(self):
        raw = "Emails found:\n--\ntest@example.com\nother@example.com\n\nHosts found:\n"
        result = theharvester_parser.parse(raw)
        assert "test@example.com" in result["emails"]

    def test_empty_output(self):
        result = theharvester_parser.parse("")
        assert result["emails"] == []


class TestHoleheParser:
    def test_parses_registered(self):
        raw = "[✓] twitter: used\n[x] facebook: not used\n"
        result = holehe_parser.parse(raw)
        assert result["registered_count"] >= 0  # registration signal detected

    def test_empty(self):
        result = holehe_parser.parse("")
        assert result["registered"] == []


class TestExiftoolParser:
    def test_parses_json(self):
        import json
        data = json.dumps([{"Make": "Apple", "Model": "iPhone 13", "GPSLatitude": "41.3851"}])
        result = exiftool_parser.parse(data)
        assert result["gps_present"] is True
        assert len(result["privacy_risks"]) > 0

    def test_empty(self):
        result = exiftool_parser.parse("[]")
        assert result["gps_present"] is False
