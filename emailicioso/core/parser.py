"""Robust parser for .eml (RFC 5322 / MIME) and Outlook .msg files.

Design goals:
- Never crash on malformed input: degrade gracefully and record what went wrong.
- Keep every header occurrence in order (several Received / Authentication-Results).
- Treat attached emails (message/rfc822, .msg) as attachments that can be opened as
  a new analysis instead of silently merging their bodies into the parent.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from email import policy
from email.message import Message
from email.parser import BytesParser
from pathlib import Path

from emailicioso.core.models import AttachmentInfo, ParsedEmail

OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
MAX_DEPTH = 25
_B64_BLOCK_RE = re.compile(r"^[A-Za-z0-9+/=\r\n]+$")
_FOLD_RE = re.compile(r"\r?\n[ \t]+")


class ParseError(Exception):
    """Raised when a file cannot be interpreted as an email at all."""


# --------------------------------------------------------------------------- helpers


def _decode_bytes(data: bytes, charset: str | None = None) -> str:
    if not data:
        return ""
    for enc in [c for c in (charset, "utf-8", "cp1252") if c]:
        try:
            return data.decode(enc)
        except (LookupError, UnicodeDecodeError):
            continue
    return data.decode("latin-1", errors="replace")


def _maybe_base64(text: str, depth: int = 0) -> str:
    """Decode bodies that are base64 blobs without a Content-Transfer-Encoding header.

    Some web clients and broken forwarders emit them. Only applies to text made
    exclusively of base64 characters that decodes into mostly printable text.
    """
    if depth > 3 or not text:
        return text
    stripped = text.strip()
    if len(stripped) < 20 or not _B64_BLOCK_RE.match(stripped):
        return text
    cleaned = re.sub(r"\s+", "", stripped)
    if len(cleaned) % 4 not in (0, 2, 3):
        return text
    try:
        raw = base64.b64decode(cleaned + "=" * (-len(cleaned) % 4), validate=True)
    except (binascii.Error, ValueError):
        return text
    decoded = _decode_bytes(raw)
    if not decoded:
        return text
    printable = sum(1 for c in decoded if c.isprintable() or c in "\r\n\t")
    if printable / len(decoded) < 0.95:
        return text
    return _maybe_base64(decoded, depth + 1)


def _unwrap_whole_file_base64(raw: bytes) -> bytes:
    """Some exports wrap the entire .eml in base64. Detect and unwrap it."""
    sample = raw[:400].decode("ascii", errors="ignore")
    if not sample or not _B64_BLOCK_RE.match(sample.strip() or "-"):
        return raw
    try:
        cleaned = re.sub(rb"\s+", b"", raw)
        decoded = base64.b64decode(cleaned, validate=True)
    except (binascii.Error, ValueError):
        return raw
    head = decoded[:2000].decode("utf-8", errors="ignore")
    if re.search(r"^(From|Subject|Received|Date|MIME-Version|Return-Path):", head, re.M | re.I):
        return decoded
    return raw


def _split_raw_headers(raw: bytes) -> str:
    for sep in (b"\r\n\r\n", b"\n\n"):
        idx = raw.find(sep)
        if idx != -1:
            return _decode_bytes(raw[:idx]).replace("\r\n", "\n")
    return _decode_bytes(raw[:65536]).replace("\r\n", "\n")


def _header_items(msg: Message) -> list[tuple[str, str]]:
    items: list[tuple[str, str]] = []
    for name, value in msg.raw_items():
        try:
            text = str(msg.policy.header_fetch_parse(name, value))
        except Exception:  # malformed header: keep the raw value
            text = str(value)
        items.append((name, _FOLD_RE.sub(" ", text).strip()))
    return items


def _part_text(part: Message) -> str:
    try:
        content = part.get_content()  # type: ignore[attr-defined]
        if isinstance(content, str):
            return content
        if isinstance(content, bytes):
            return _decode_bytes(content, part.get_content_charset())
    except Exception:
        pass
    payload = part.get_payload(decode=True)
    if isinstance(payload, bytes):
        return _decode_bytes(payload, part.get_content_charset())
    raw = part.get_payload(decode=False)
    return raw if isinstance(raw, str) else ""


def _part_bytes(part: Message) -> bytes:
    try:
        payload = part.get_payload(decode=True)
    except Exception:
        payload = None
    if isinstance(payload, bytes):
        return payload
    raw = part.get_payload(decode=False)
    if isinstance(raw, str):
        return raw.encode("utf-8", errors="replace")
    return b""


def _message_bytes(msg: Message) -> bytes:
    try:
        return msg.as_bytes(policy=policy.default.clone(linesep="\r\n"))
    except Exception:
        try:
            return msg.as_string().encode("utf-8", errors="replace")
        except Exception:
            return b""


def _safe_header(msg: Message, name: str) -> str:
    try:
        value = msg.get(name)
    except Exception:
        return ""
    return _FOLD_RE.sub(" ", str(value)).strip() if value is not None else ""


# --------------------------------------------------------------------------- MIME walk


def _walk(
    part: Message,
    text_parts: list[str],
    html_parts: list[str],
    attachments: list[AttachmentInfo],
    defects: list[str],
    depth: int = 0,
) -> None:
    if depth > MAX_DEPTH:
        defects.append("MIME nesting too deep (truncated)")
        return
    defects.extend(type(d).__name__ for d in getattr(part, "defects", []) or [])

    ctype = part.get_content_type()
    maintype = part.get_content_maintype()

    if ctype == "message/rfc822":
        payload = part.get_payload()
        inner = payload[0] if isinstance(payload, list) and payload else None
        data = _message_bytes(inner) if isinstance(inner, Message) else _part_bytes(part)
        subject = _safe_header(inner, "Subject") if isinstance(inner, Message) else ""
        name = part.get_filename() or f"{subject or 'attached-message'}.eml"
        attachments.append(
            AttachmentInfo(
                filename=name,
                content_type=ctype,
                size=len(data),
                payload=data,
                is_email=True,
            )
        )
        return

    if part.is_multipart():
        payload = part.get_payload()
        if isinstance(payload, list):
            for sub in payload:
                if isinstance(sub, Message):
                    _walk(sub, text_parts, html_parts, attachments, defects, depth + 1)
        return

    try:
        filename = part.get_filename()
    except Exception:
        filename = None
    disposition = (part.get_content_disposition() or "").lower()
    cid = _safe_header(part, "Content-ID") or None

    is_attachment = (
        disposition == "attachment"
        or filename is not None
        or maintype not in ("text",)
        or ctype == "text/calendar"
    )

    if is_attachment:
        data = _part_bytes(part)
        is_msg = ctype == "application/vnd.ms-outlook" or (filename or "").lower().endswith(".msg")
        attachments.append(
            AttachmentInfo(
                filename=filename or _default_name(ctype, len(attachments) + 1),
                content_type=ctype,
                size=len(data),
                payload=data,
                content_id=cid,
                is_inline=disposition == "inline" or (cid is not None and disposition != "attachment"),
                is_email=is_msg and data.startswith(OLE_MAGIC),
            )
        )
        return

    text = _maybe_base64(_part_text(part))
    if not text.strip():
        return
    if ctype == "text/html":
        html_parts.append(text)
    else:
        text_parts.append(text)


def _default_name(ctype: str, n: int) -> str:
    ext = {
        "image/png": ".png",
        "image/jpeg": ".jpg",
        "image/gif": ".gif",
        "application/pdf": ".pdf",
        "text/calendar": ".ics",
        "application/zip": ".zip",
    }.get(ctype, ".bin")
    return f"part-{n}{ext}"


# --------------------------------------------------------------------------- public API


def parse_eml_bytes(raw: bytes, path: Path | None = None) -> ParsedEmail:
    original_sha256 = hashlib.sha256(raw).hexdigest()
    raw = _unwrap_whole_file_base64(raw)
    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw)
    except Exception as exc:  # pragma: no cover - the stdlib parser is very forgiving
        raise ParseError(f"Could not parse message: {exc}") from exc

    text_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[AttachmentInfo] = []
    defects: list[str] = []
    _walk(msg, text_parts, html_parts, attachments, defects)

    items = _header_items(msg)
    if not items and not text_parts and not html_parts:
        raise ParseError("The file does not look like an email (no headers and no body found).")

    return ParsedEmail(
        path=path,
        source_format="eml",
        raw_headers=_split_raw_headers(raw),
        header_items=items,
        subject=_safe_header(msg, "Subject"),
        from_=_safe_header(msg, "From"),
        to=_safe_header(msg, "To"),
        cc=_safe_header(msg, "Cc"),
        date=_safe_header(msg, "Date"),
        message_id=_safe_header(msg, "Message-ID"),
        text_body="\n\n".join(p.strip("\r\n") for p in text_parts),
        html_body="\n<hr>\n".join(html_parts),
        attachments=attachments,
        size=len(raw),
        sha256=original_sha256,
        defects=sorted(set(defects)),
    )


def parse_msg_bytes(raw: bytes, path: Path | None = None) -> ParsedEmail:
    try:
        import extract_msg  # type: ignore[import-not-found]
    except ImportError as exc:
        raise ParseError(
            "Outlook .msg support needs the optional 'extract-msg' package.\n"
            "Install it with:  pip install extract-msg"
        ) from exc

    try:
        msg = extract_msg.openMsg(raw)
    except Exception as exc:
        raise ParseError(f"Could not open .msg file: {exc}") from exc

    try:
        header_msg = msg.header
        items = _header_items(header_msg) if header_msg is not None else []
        raw_headers = str(header_msg).split("\n\n", 1)[0] if header_msg is not None else ""

        def hdr(name: str, fallback: str | None) -> str:
            for k, v in items:
                if k.lower() == name.lower():
                    return v
            return str(fallback or "")

        html = msg.htmlBody or b""
        html_text = _decode_bytes(html) if isinstance(html, bytes) else str(html)

        attachments: list[AttachmentInfo] = []
        for att in msg.attachments:
            data = getattr(att, "data", None)
            name = (
                getattr(att, "longFilename", None)
                or getattr(att, "shortFilename", None)
                or getattr(att, "name", None)
                or f"attachment-{len(attachments) + 1}"
            )
            is_email = False
            if isinstance(data, bytes):
                payload = data
            elif data is not None and hasattr(data, "exportBytes"):
                try:
                    payload = data.exportBytes()
                except Exception:
                    payload = b""
                is_email = True
                if not str(name).lower().endswith(".msg"):
                    name = f"{name}.msg"
            else:
                payload = b""
            cid = getattr(att, "cid", None) or getattr(att, "contentId", None)
            attachments.append(
                AttachmentInfo(
                    filename=str(name),
                    content_type=str(getattr(att, "mimetype", None) or "application/octet-stream"),
                    size=len(payload),
                    payload=payload,
                    content_id=str(cid) if cid else None,
                    is_inline=bool(getattr(att, "hidden", False)) or bool(cid),
                    is_email=is_email,
                )
            )

        date = msg.date
        return ParsedEmail(
            path=path,
            source_format="msg",
            raw_headers=raw_headers.replace("\r\n", "\n"),
            header_items=items,
            subject=hdr("Subject", msg.subject),
            from_=hdr("From", msg.sender),
            to=hdr("To", msg.to),
            cc=hdr("Cc", msg.cc),
            date=hdr("Date", date.isoformat() if hasattr(date, "isoformat") else date),
            message_id=hdr("Message-ID", getattr(msg, "messageId", "")),
            text_body=str(msg.body or ""),
            html_body=html_text,
            attachments=attachments,
            size=len(raw),
            sha256=hashlib.sha256(raw).hexdigest(),
        )
    finally:
        try:
            msg.close()
        except Exception:
            pass


def parse_bytes(raw: bytes, path: Path | None = None) -> ParsedEmail:
    if raw.startswith(OLE_MAGIC):
        return parse_msg_bytes(raw, path)
    return parse_eml_bytes(raw, path)


def parse_file(path: str | Path) -> ParsedEmail:
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"File not found: {p}")
    return parse_bytes(p.read_bytes(), p)


def html_with_inline_images(parsed: ParsedEmail) -> str:
    """HTML body with cid: references replaced by data: URIs, for local rendering."""
    html = parsed.html_body
    if not html:
        return html
    for att in parsed.attachments:
        if not att.content_id or not att.payload:
            continue
        cid = att.content_id.strip().strip("<>")
        if f"cid:{cid}" not in html:
            continue
        b64 = base64.b64encode(att.payload).decode("ascii")
        html = html.replace(f"cid:{cid}", f"data:{att.content_type};base64,{b64}")
    return html
