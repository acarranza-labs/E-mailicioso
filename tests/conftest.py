from __future__ import annotations

import io
import os
import sys
import tempfile
import zipfile
from email import policy
from email.message import EmailMessage
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
# Never touch the real user profile from tests.
os.environ.setdefault("EMAILICIOSO_HOME", tempfile.mkdtemp(prefix="emailicioso-tests-"))

DEMO = ROOT / "samples" / "demo-phishing.eml"


def build_email(
    *,
    subject: str = "Hello",
    from_: str = "Alice <alice@example.org>",
    to: str = "bob@contoso.com",
    text: str | None = "Hi Bob",
    html: str | None = None,
    headers: list[tuple[str, str]] | None = None,
    attachments: list[tuple[str, bytes, str]] | None = None,
) -> bytes:
    msg = EmailMessage(policy=policy.SMTP)
    for k, v in headers or []:
        msg[k] = v
    msg["From"] = from_
    msg["To"] = to
    msg["Subject"] = subject
    msg["Date"] = "Mon, 06 Oct 2025 10:00:00 +0000"
    msg["Message-ID"] = "<test-1@example.org>"
    if text is not None:
        msg.set_content(text)
    if html is not None:
        if text is None:
            msg.set_content(html, subtype="html")
        else:
            msg.add_alternative(html, subtype="html")
    for name, data, ctype in attachments or []:
        maintype, subtype = ctype.split("/", 1)
        msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=name)
    return msg.as_bytes()


def make_zip(files: dict[str, bytes], encrypted: bool = False) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    data = bytearray(buf.getvalue())
    if encrypted:
        # Set the "encrypted" general purpose flag in local and central headers.
        i = 0
        while (i := data.find(b"PK\x03\x04", i)) != -1:
            data[i + 6] |= 0x1
            i += 4
        i = 0
        while (i := data.find(b"PK\x01\x02", i)) != -1:
            data[i + 8] |= 0x1
            i += 4
    return bytes(data)


@pytest.fixture
def demo_result():
    from emailicioso.core.analyzer import analyze_file

    return analyze_file(DEMO)
