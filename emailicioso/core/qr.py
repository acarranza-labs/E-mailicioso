"""Optional QR code decoding for image attachments (quishing).

Uses OpenCV's built-in QR detector when ``opencv-python-headless`` is installed.
Without it, this module silently does nothing.
"""

from __future__ import annotations

from emailicioso.core.models import AttachmentInfo

IMAGE_TYPES = ("PNG image", "JPEG image", "GIF image", "BMP image", "WEBP image", "TIFF image")


def available() -> bool:
    try:
        import cv2  # noqa: F401
        import numpy  # noqa: F401
    except ImportError:
        return False
    return True


def decode_qr(data: bytes) -> list[str]:
    try:
        import cv2
        import numpy as np
    except ImportError:
        return []
    try:
        arr = np.frombuffer(data, dtype=np.uint8)
        img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
        if img is None:
            return []
        detector = cv2.QRCodeDetector()
        results: list[str] = []
        ok, decoded, _points, _ = detector.detectAndDecodeMulti(img)
        if ok:
            results.extend(d for d in decoded if d)
        if not results:
            text, _pts, _ = detector.detectAndDecode(img)
            if text:
                results.append(text)
        if not results:
            # Small QR codes in big images: try upscaling once.
            big = cv2.resize(img, None, fx=2, fy=2, interpolation=cv2.INTER_NEAREST)
            text, _pts, _ = detector.detectAndDecode(big)
            if text:
                results.append(text)
        return list(dict.fromkeys(results))
    except Exception:
        return []


def scan_attachments(attachments: list[AttachmentInfo]) -> list[tuple[str, str]]:
    """Return (attachment filename, decoded payload) for every QR code found."""
    if not available():
        return []
    found = []
    for att in attachments:
        if att.detected_type in IMAGE_TYPES and 0 < att.size < 15_000_000:
            for payload in decode_qr(att.payload):
                found.append((att.filename, payload))
    return found
