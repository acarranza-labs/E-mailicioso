import pytest

from emailicioso.core import domains as dom


@pytest.mark.parametrize(
    "host,expected",
    [
        ("paypa1.com", ("paypal", "lookalike")),
        ("rnicrosoft.com", ("microsoft", "lookalike")),
        ("micosoft.com", ("microsoft", "lookalike")),
        ("xn--pypal-4ve.com", ("paypal", "lookalike")),
        ("microsoft-login-secure.com", ("microsoft", "brand-in-domain")),
        ("login.microsoft.com.evil-site.net", ("microsoft", "brand-in-subdomain")),
        ("santander.xyz", ("santander", "brand-other-tld")),
    ],
)
def test_brand_impersonation(host, expected):
    assert dom.brand_impersonation(host) == expected


@pytest.mark.parametrize(
    "host",
    ["login.microsoftonline.com", "www.paypal.com", "pineapple.com", "googleadservices.com",
     "dropboxusercontent.com", "example.com", "amazon.co.uk", "accounts.google.com"],
)
def test_no_false_positive_for_legit_or_unrelated(host):
    assert dom.brand_impersonation(host) is None


def test_registered_domain_offline():
    assert dom.registered_domain("a.b.example.co.uk") == "example.co.uk"
    assert dom.registered_domain("203.0.113.1") == "203.0.113.1"


def test_public_ip():
    assert dom.is_public_ip("8.8.8.8")
    assert dom.is_public_ip("203.0.113.5")  # documentation ranges count as external
    for ip in ("10.1.2.3", "192.168.0.1", "172.20.1.1", "127.0.0.1", "100.64.1.1", "fe80::1", "::1", "nope"):
        assert not dom.is_public_ip(ip)


def test_defang_and_refang_roundtrip():
    url = "https://evil.example.com/a.b?x=y"
    d = dom.defang(url)
    assert d == "hxxps://evil[.]example[.]com/a.b?x=y"
    assert dom.refang(d) == url
    assert dom.defang("1.2.3.4") == "1[.]2[.]3[.]4"
    assert dom.defang("user@evil.com") == "user[@]evil[.]com"
    assert dom.defang("evil.com") == "evil[.]com"
