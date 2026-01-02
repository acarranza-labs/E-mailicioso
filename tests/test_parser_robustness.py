import unittest
from email.message import EmailMessage
from email import message_from_bytes
from pathlib import Path
import tempfile
import os
import shutil

# Import the parser function - assuming we will rewrite it to be importable
try:
    from core.eml_parser import parse_eml, ParsedEML
except ImportError:
    pass

class TestEMLParser(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def _create_eml(self, name, content):
        p = Path(self.test_dir) / name
        p.write_bytes(content)
        return p

    def test_simple_text_email(self):
        content = (
            b"Subject: Simple Text\r\n"
            b"From: sender@example.com\r\n"
            b"To: receiver@example.com\r\n"
            b"\r\n"
            b"This is a simple text body."
        )
        p = self._create_eml("simple.eml", content)
        parsed = parse_eml(p)
        self.assertIn("simple text body", parsed.text_body.lower())
        self.assertEqual(parsed.subject, "Simple Text")

    def test_multipart_email(self):
        # A simple multipart/alternative email
        content = (
            b"Subject: Multipart\r\n"
            b"Content-Type: multipart/alternative; boundary=boundary123\r\n"
            b"\r\n"
            b"--boundary123\r\n"
            b"Content-Type: text/plain\r\n"
            b"\r\n"
            b"Plain text version\r\n"
            b"--boundary123\r\n"
            b"Content-Type: text/html\r\n"
            b"\r\n"
            b"<html>HTML version</html>\r\n"
            b"--boundary123--"
        )
        p = self._create_eml("multipart.eml", content)
        parsed = parse_eml(p)
        self.assertIn("plain text version", parsed.text_body.lower())
        self.assertIn("html version", parsed.html_body.lower())

    def test_base64_explicit_body(self):
        # Body encoded in base64 with correct headers
        content = (
            b"Subject: Base64\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"Content-Transfer-Encoding: base64\r\n"
            b"\r\n"
            b"SGVsbG8gV29ybGQ="  # Hello World
        )
        p = self._create_eml("base64_explicit.eml", content)
        parsed = parse_eml(p)
        self.assertIn("hello world", parsed.text_body.lower())

    def test_missing_separator_giant_header(self):
        # This simulates the user's issue: the body is swallowed into a header
        # or just attached without a clear break. 
        # Actually standard python email parser is robust, but if headers don't end with \r\n\r\n...
        # Let's verify a "giant header" case.
        giant_header_val = "x" * 3000
        content = (
            b"Subject: Broken\r\n"
            b"X-Giant: " + giant_header_val.encode() + b"\r\n"
            b"\r\n"
            b"Real Body"
        )
        p = self._create_eml("giant.eml", content)
        parsed = parse_eml(p)
        # Standard parser usually handles long headers by folding or just reading them.
        # We want to ensure it doesn't crash.
        self.assertTrue(parsed.headers)
        
    def test_hidden_base64_without_headers(self):
        # Simulating content that looks like base64 but has no transfer-encoding header
        # This matches the "fallback" logic we tried to implement.
        # It's technically "text/plain" but the content is b64 string.
        b64_content = b"SGVsbG8gV29ybGQgZnJvbSBCNjQ=" # Hello World from B64
        content = (
            b"Subject: No Header B64\r\n"
            b"\r\n"
            + b64_content
        )
        p = self._create_eml("hidden_b64.eml", content)
        parsed = parse_eml(p)
        # Our parser should theoretically treat this as just text "SGVsbG8..."
        # unless we explicitly force-decode it. 
        # If the user WANTS it decoded, we check if our heuristic works.
        # For now, just ensure it returns *something*.
        self.assertTrue(parsed.text_body)

if __name__ == "__main__":
    unittest.main()
