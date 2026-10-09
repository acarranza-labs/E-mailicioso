from conftest import build_email
from emailicioso.core.headers import analyze_headers, parse_auth_header, parse_received
from emailicioso.core.models import Severity
from emailicioso.core.parser import parse_eml_bytes


def titles(rep):
    return {f.title for f in rep.findings}


def test_parse_microsoft_authentication_results():
    value = ("spf=pass (sender IP is 1.2.3.4) smtp.mailfrom=x.com; dkim=pass (signature was verified) "
             "header.d=x.com;dmarc=fail action=quarantine header.from=y.com;compauth=fail reason=000")
    res = {a.mechanism: a.result for a in parse_auth_header(value, "Authentication-Results")}
    assert res == {"SPF": "pass", "DKIM": "pass", "DMARC": "fail", "CompAuth": "fail"}


def test_semicolons_inside_comments_are_ignored():
    value = "mx.google.com; spf=pass (google.com: domain of a@b.com; designates 1.2.3.4) smtp.mailfrom=a@b.com"
    res = parse_auth_header(value, "x")
    assert len(res) == 1 and res[0].result == "pass"


def test_received_postfix_uses_ip_in_comment_not_helo():
    host, ip, by, proto, ts = parse_received(
        "from [192.168.1.20] (unknown [198.51.100.23]) by mail.relay.example (Postfix) with ESMTPSA id X; "
        "Tue, 7 Oct 2025 09:14:21 +0000 (UTC)")
    assert ip == "198.51.100.23"
    assert by == "mail.relay.example"
    assert proto == "ESMTPSA"
    assert ts is not None and ts.year == 2025


def test_hops_are_chronological_and_originating_ip():
    raw = build_email(headers=[
        ("Received", "from mx.contoso.com (10.0.0.5) by mbx.contoso.com; Mon, 6 Oct 2025 10:00:09 +0000"),
        ("Received", "from out.sender.example (out.sender.example [203.0.113.9]) by mx.contoso.com with ESMTPS; "
                     "Mon, 6 Oct 2025 10:00:05 +0000"),
        ("Received", "from laptop (unknown [10.1.1.1]) by out.sender.example with ESMTPSA; Mon, 6 Oct 2025 10:00:00 +0000"),
    ])
    rep = analyze_headers(parse_eml_bytes(raw))
    assert [h.index for h in rep.hops] == [1, 2, 3]
    assert rep.hops[0].by_host == "out.sender.example"
    assert rep.hops[1].delay_seconds == 5
    assert rep.originating_ip == "203.0.113.9"


def test_x_originating_ip_wins():
    raw = build_email(headers=[("X-Originating-IP", "[198.51.100.40]")])
    assert analyze_headers(parse_eml_bytes(raw)).originating_ip == "198.51.100.40"


def test_reply_to_to_freemail_is_high():
    raw = build_email(from_="CFO <cfo@acme-corp.com>", headers=[("Reply-To", "cfo.acme@gmail.com")])
    rep = analyze_headers(parse_eml_bytes(raw))
    f = next(f for f in rep.findings if f.title.startswith("Reply-To"))
    assert f.severity == Severity.HIGH


def test_display_name_spoofing():
    raw = build_email(from_='"ceo@contoso.com" <random123@gmail.com>')
    assert "Display name shows a different email address" in titles(analyze_headers(parse_eml_bytes(raw)))


def test_display_name_brand_and_lookalike_domain():
    raw = build_email(from_="PayPal Service <service@paypa1.com>")
    t = titles(analyze_headers(parse_eml_bytes(raw)))
    assert "Display name impersonates Paypal" in t
    assert any(x.startswith("Sender domain imitates Paypal (lookalike)") for x in t)


def test_legit_brand_sender_is_quiet():
    raw = build_email(from_="Microsoft account team <account-security-noreply@accountprotection.microsoft.com>",
                      headers=[("Authentication-Results",
                                "spf=pass smtp.mailfrom=accountprotection.microsoft.com; dkim=pass; dmarc=pass")])
    rep = analyze_headers(parse_eml_bytes(raw))
    assert not [f for f in rep.findings if f.severity >= Severity.LOW]


def test_fake_reply_subject():
    raw = build_email(subject="RE: Invoice 2291")
    assert "Fake reply subject" in titles(analyze_headers(parse_eml_bytes(raw)))
    raw2 = build_email(subject="RE: Invoice 2291", headers=[("In-Reply-To", "<a@b>")])
    assert "Fake reply subject" not in titles(analyze_headers(parse_eml_bytes(raw2)))


def test_dmarc_fail_finding():
    raw = build_email(headers=[("Authentication-Results", "mx; spf=fail smtp.mailfrom=x.com; dmarc=fail")])
    t = titles(analyze_headers(parse_eml_bytes(raw)))
    assert "DMARC failed" in t and "SPF failed" in t


def test_microsoft_gateway_verdict():
    raw = build_email(headers=[("X-Forefront-Antispam-Report",
                                "CIP:203.0.113.4;CTRY:NL;SCL:9;SFV:SPM;CAT:HPHSH;DIR:INB;"),
                               ("X-MS-Exchange-Organization-Network-Message-Id", "abcd-1234")])
    rep = analyze_headers(parse_eml_bytes(raw))
    assert rep.network_message_id == "abcd-1234"
    assert any(g.field == "CAT" and g.value == "HPHSH" and g.suspicious for g in rep.gateway)
    assert any(f.title.startswith("Microsoft Defender classified it as High confidence phishing")
               for f in rep.findings)


def test_proofpoint_gateway_verdict():
    raw = build_email(headers=[("X-Proofpoint-Spam-Details",
                                "rule=phish policy=default score=95 phishscore=99 spamscore=10 bulkscore=0")])
    rep = analyze_headers(parse_eml_bytes(raw))
    assert "Proofpoint scored it as malicious" in titles(rep)
