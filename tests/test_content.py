from conftest import build_email
from emailicioso.core.content import analyze_content, find_ibans
from emailicioso.core.models import Severity
from emailicioso.core.parser import parse_eml_bytes


def titles(text="", html=None, subject="Hola"):
    return {f.title: f for f in analyze_content(parse_eml_bytes(build_email(text=text, html=html, subject=subject)))}


def test_bec_bank_change_spanish():
    t = titles("Buenos días, le informamos de nuestra nueva cuenta bancaria. "
               "Realice los pagos a la nueva cuenta: ES91 2100 0418 4502 0005 1332. Es urgente.")
    assert t["Asks to change bank/payment details"].severity == Severity.HIGH
    assert "ES91 2100 0418 4502 0005 1332" in t["Contains 1 bank account number(s) (IBAN)"].evidence


def test_iban_checksum():
    assert find_ibans("GB82 WEST 1234 5698 7654 32") == ["GB82 WEST 1234 5698 7654 32"]
    assert find_ibans("ES00 1234 1234 1234 1234 1234") == []


def test_credential_lure_with_urgency():
    t = titles("Your mailbox is full. Verify your account immediately or it will be suspended.")
    assert t["Credential lure with urgency"].severity == Severity.MEDIUM


def test_callback_phishing():
    t = titles("Thank you for your order. Your subscription renewal of $499 was processed. "
               "To cancel and get a refund call +1 (808) 555-0142.")
    assert "Callback phishing pattern (TOAD)" in t


def test_hidden_text():
    html = ('<p>Hi</p><div style="display:none">lorem ipsum dolor sit amet consectetur adipiscing elit sed do '
            'eiusmod tempor</div>')
    assert "Hidden text in HTML body" in titles("Hi", html)


def test_benign_email_has_no_findings():
    assert titles("Hi team, the meeting moved to 3pm. See you there.") == {}
