import base64

import pytest

from conftest import build_email
from emailicioso.core.parser import ParseError, parse_bytes, parse_eml_bytes


def test_simple_text_email():
    raw = (b"Subject: Simple Text\r\nFrom: sender@example.com\r\nTo: receiver@example.com\r\n\r\n"
           b"This is a simple text body.")
    p = parse_eml_bytes(raw)
    assert p.subject == "Simple Text"
    assert "simple text body" in p.text_body.lower()
    assert len(p.sha256) == 64


def test_multipart_alternative():
    p = parse_eml_bytes(build_email(text="Plain version", html="<p>HTML version</p>"))
    assert "Plain version" in p.text_body
    assert "HTML version" in p.html_body


def test_base64_body_with_header():
    raw = (b"Subject: B64\r\nContent-Type: text/plain; charset=utf-8\r\n"
           b"Content-Transfer-Encoding: base64\r\n\r\nSGVsbG8gV29ybGQ=")
    assert "Hello World" in parse_eml_bytes(raw).text_body


def test_hidden_base64_body_without_header_is_decoded():
    payload = base64.b64encode(b"Please review the attached invoice today.").decode()
    raw = f"Subject: no cte\r\n\r\n{payload}".encode()
    assert "attached invoice" in parse_eml_bytes(raw).text_body


def test_normal_text_is_not_mangled_by_base64_heuristic():
    raw = b"Subject: t\r\n\r\nThisLooksLikeOneLongWordButItIsNotBase64AtAll"
    assert parse_eml_bytes(raw).text_body.startswith("ThisLooksLike")


def test_whole_file_base64_wrapped():
    inner = build_email(subject="Wrapped")
    p = parse_eml_bytes(base64.encodebytes(inner))
    assert p.subject == "Wrapped"


def test_giant_header_does_not_crash():
    raw = b"Subject: Broken\r\nX-Giant: " + b"x" * 5000 + b"\r\n\r\nReal Body"
    p = parse_eml_bytes(raw)
    assert p.header("X-Giant").startswith("xxx")
    assert "Real Body" in p.text_body


def test_all_received_headers_are_kept_in_order():
    raw = build_email(headers=[
        ("Received", "from c.example (c.example [203.0.113.3]) by d.example; Mon, 6 Oct 2025 10:00:03 +0000"),
        ("Received", "from b.example (b.example [203.0.113.2]) by c.example; Mon, 6 Oct 2025 10:00:02 +0000"),
        ("Received", "from a.example (a.example [203.0.113.1]) by b.example; Mon, 6 Oct 2025 10:00:01 +0000"),
    ])
    p = parse_eml_bytes(raw)
    received = p.headers_all("Received")
    assert len(received) == 3
    assert "203.0.113.3" in received[0]


def test_non_utf8_charset_and_encoded_subject():
    raw = (b"Subject: =?iso-8859-1?q?Factura_pendiente_de_pago_=E1?=\r\n"
           b"Content-Type: text/plain; charset=iso-8859-1\r\n\r\n") + "Atención: pago".encode("latin-1")
    p = parse_eml_bytes(raw)
    assert p.subject.startswith("Factura pendiente")
    assert "Atención" in p.text_body


def test_attached_email_is_an_attachment_not_merged():
    inner = build_email(subject="Original phish", text="Click here now")
    outer = build_email(subject="FW: reported", text="Please check this",
                        attachments=[("phish.eml", inner, "message/rfc822")])
    p = parse_eml_bytes(outer)
    assert "Click here now" not in p.text_body
    emails = [a for a in p.attachments if a.is_email]
    assert len(emails) == 1
    nested = parse_bytes(emails[0].payload)
    assert nested.subject == "Original phish"
    assert "Click here now" in nested.text_body


def test_inline_image_and_cid_rendering():
    from email import policy
    from email.message import EmailMessage

    from emailicioso.core.parser import html_with_inline_images

    msg = EmailMessage(policy=policy.SMTP)
    msg["Subject"] = "img"
    msg.set_content("text")
    msg.add_alternative('<img src="cid:logo123">', subtype="html")
    msg.get_payload()[1].add_related(b"\x89PNG\r\n\x1a\nfake", maintype="image", subtype="png", cid="<logo123>")
    p = parse_eml_bytes(msg.as_bytes())
    assert any(a.is_inline for a in p.attachments)
    assert "data:image/png;base64," in html_with_inline_images(p)


def test_garbage_raises_parse_error():
    with pytest.raises(ParseError):
        parse_eml_bytes(b"")


def test_msg_without_extract_msg_gives_clear_error(monkeypatch):
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "extract_msg":
            raise ImportError("no module")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(ParseError, match="extract-msg"):
        parse_bytes(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 600)
