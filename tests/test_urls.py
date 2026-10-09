from emailicioso.core.models import Severity
from emailicioso.core.urls import assess, collect, extract_emails, unwrap, url_findings


def test_safelinks_unwrap():
    url = ("https://eur03.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.example.net%2Flogin"
           "&data=05%7C01&reserved=0")
    final, chain = unwrap(url)
    assert final == "https://evil.example.net/login"
    assert chain == ["Microsoft Safe Links"]


def test_proofpoint_v2_unwrap():
    url = ("https://urldefense.proofpoint.com/v2/url?u=https-3A__media.mnn.com_assets_images_2016_06_"
           "jupiter-2Dnasa.jpg.638x0-5Fq80-5Fcrop-2Dsmart.jpg&d=DwMBaQ&c=x&r=y")
    assert unwrap(url)[0] == "https://media.mnn.com/assets/images/2016/06/jupiter-nasa.jpg.638x0_q80_crop-smart.jpg"


def test_proofpoint_v3_unwrap():
    url = ("https://urldefense.com/v3/__https://google.com:443/search?q=a*test&gs=ps__;Kw!-612Flbf0JvQ3kNJkRi5Jg"
           "!Ue6tQudNKaShHg93trcdjqDP8se2ySE65jyCIe2K1D_uNjZ1Lnf6YLQERujngZv9UWf66ujQIQ$")
    assert unwrap(url) == ("https://google.com:443/search?q=a+test&gs=ps", ["Proofpoint URL Defense v3"])


def test_nested_wrappers():
    url = ("https://eur01.safelinks.protection.outlook.com/?url=https%3A%2F%2Furldefense.com%2Fv3%2F__https%3A"
           "%2F%2Fevil.example.com%2Flogin__%3B!!abc%24&data=05")
    final, chain = unwrap(url)
    assert final == "https://evil.example.com/login"
    assert chain == ["Microsoft Safe Links", "Proofpoint URL Defense v3"]


def test_base64_redirect_parameter():
    final, chain = unwrap("https://click.example.com/track?u=aHR0cHM6Ly9ldmlsLnh5ei9h")
    assert final == "https://evil.xyz/a"
    assert chain and chain[0].startswith("Redirect parameter")


def test_link_text_mismatch_is_high():
    info = assess("https://secure-account.example.top/x", "html", "https://www.paypal.com/signin")
    assert info.severity == Severity.HIGH
    assert any(f.startswith("Link text shows www.paypal.com") for f in info.flags)


def test_matching_link_text_is_fine():
    info = assess("https://www.paypal.com/signin?x=1", "html", "www.paypal.com")
    assert not any(f.startswith("Link text") for f in info.flags)


def test_userinfo_trick_and_ip_and_punycode():
    assert "Userinfo '@' trick in URL" in assess("http://www.bank.com@203.0.113.5/login", "text").flags
    assert "IP address instead of domain" in assess("http://203.0.113.5/a", "text").flags
    puny = assess("https://xn--pypal-4ve.com/", "text")
    assert any(f.startswith("Punycode domain") for f in puny.flags)


def test_collect_dedupes_and_prefers_anchor_text():
    html = '<a href="https://evil.example.net/a">https://bank.com</a><p>also https://evil.example.net/a</p>'
    urls = collect("see https://evil.example.net/a", html)
    assert len(urls) == 1
    assert urls[0].display_text == "https://bank.com"
    assert urls[0].severity == Severity.HIGH


def test_anchor_text_url_is_not_extracted_as_link():
    urls = collect("", '<a href="https://evil.example.net/a">https://www.microsoft.com</a>')
    assert [u.url for u in urls] == ["https://evil.example.net/a"]


def test_form_and_resources():
    html = '<form action="https://collect.example.top/p"></form><img src="https://t.example.com/p.gif">'
    urls = {u.source: u for u in collect("", html)}
    assert "HTML form posts data from inside the email" in urls["html-form"].flags
    assert "html-resource" in urls


def test_findings_are_aggregated_per_flag():
    urls = collect("https://bit.ly/a https://bit.ly/b https://tinyurl.com/c", "")
    fs = [f for f in url_findings(urls) if f.title == "URL shortener hides the destination"]
    assert len(fs) == 1 and len(fs[0].evidence) == 3


def test_trailing_punctuation_is_trimmed():
    urls = collect("Go to https://example.com/path). Thanks, or (https://example.org/x).", "")
    assert [u.url for u in urls] == ["https://example.com/path", "https://example.org/x"]


def test_extract_emails():
    assert extract_emails("write to a.b+c@Example.com, or x@y.org.") == ["a.b+c@example.com", "x@y.org"]
