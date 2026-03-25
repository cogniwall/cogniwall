from agentguard.patterns.ssn import find_ssns
from agentguard.patterns.credit_card import find_credit_cards
from agentguard.patterns.common import find_emails, find_phones


class TestSSNPattern:
    def test_standard_ssn(self):
        assert find_ssns("My SSN is 123-45-6789") == ["123-45-6789"]

    def test_ssn_no_dashes(self):
        assert find_ssns("SSN: 123456789") == ["123456789"]

    def test_ssn_with_spaces(self):
        assert find_ssns("SSN: 123 45 6789") == ["123 45 6789"]

    def test_no_ssn(self):
        assert find_ssns("No SSN here") == []

    def test_invalid_ssn_all_zeros_area(self):
        """000 area number is invalid."""
        assert find_ssns("000-45-6789") == []

    def test_invalid_ssn_900_area(self):
        """900-999 area numbers are invalid."""
        assert find_ssns("987-65-4321") == []

    def test_multiple_ssns(self):
        text = "SSNs: 123-45-6789 and 321-65-4321"
        assert find_ssns(text) == ["123-45-6789", "321-65-4321"]


class TestCreditCardPattern:
    def test_visa(self):
        assert find_credit_cards("Card: 4111111111111111") == ["4111111111111111"]

    def test_visa_with_dashes(self):
        assert find_credit_cards("Card: 4111-1111-1111-1111") == ["4111-1111-1111-1111"]

    def test_visa_with_spaces(self):
        assert find_credit_cards("Card: 4111 1111 1111 1111") == ["4111 1111 1111 1111"]

    def test_mastercard(self):
        assert find_credit_cards("Card: 5500000000000004") == ["5500000000000004"]

    def test_luhn_invalid(self):
        """A number that looks like a CC but fails Luhn check."""
        assert find_credit_cards("Card: 4111111111111112") == []

    def test_no_credit_card(self):
        assert find_credit_cards("No card here, just 12345") == []

    def test_multiple_cards(self):
        text = "Cards: 4111111111111111 and 5500000000000004"
        assert find_credit_cards(text) == ["4111111111111111", "5500000000000004"]


class TestEmailPattern:
    def test_standard_email(self):
        assert find_emails("Contact: user@example.com") == ["user@example.com"]

    def test_no_email(self):
        assert find_emails("No email here") == []

    def test_multiple_emails(self):
        text = "Emails: a@b.com and c@d.org"
        assert find_emails(text) == ["a@b.com", "c@d.org"]


class TestPhonePattern:
    def test_us_phone_dashes(self):
        assert find_phones("Call 555-123-4567") == ["555-123-4567"]

    def test_us_phone_with_country_code(self):
        assert find_phones("Call +1-555-123-4567") == ["+1-555-123-4567"]

    def test_us_phone_parens(self):
        assert find_phones("Call (555) 123-4567") == ["(555) 123-4567"]

    def test_no_phone(self):
        assert find_phones("No phone 12345") == []
