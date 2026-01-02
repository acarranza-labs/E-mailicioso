# -*- coding: utf-8 -*-
"""
Robust EML Parser.
Rewritten to handle edge cases, diverse encodings, and malformed structures safely.
"""
from __future__ import annotations

import base64
import quopri
from dataclasses import dataclass
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Dict, List, Tuple

@dataclass
class AttachmentInfo:
    filename: str
    content_type: str
    size_bytes: int
    content_id: str | None
    payload: bytes # Store raw bytes for CID/Saving

@dataclass
class ParsedEML:
    path: Path
    headers_raw: str
    headers: Dict[str, str]
    subject: str
    from_: str
    to: str
    date: str
    text_body: str
    html_body: str
    attachments: List[AttachmentInfo]

def _safe_get(msg, key: str) -> str:
    val = msg.get(key)
    return str(val) if val is not None else ""

def _decode_bytes(b: bytes, charset: str = None) -> str:
    """Helper to decode bytes with fallback strategies."""
    if not b:
        return ""
    
    encodings = []
    if charset:
        encodings.append(charset)
    encodings.extend(["utf-8", "latin-1", "cp1252", "iso-8859-1"])
    
    for enc in encodings:
        try:
            return b.decode(enc)
        except Exception:
            continue
    
    return b.decode("utf-8", errors="replace")

def _force_base64_if_needed(text: str, depth: int = 0) -> str:
    """
    Heuristic: verification if a text block is actually a single Base64 blob.
    Recursive to handle double-encoded content.
    """
    if depth > 3: # Avoid infinite recursion
        return text

    if not text:
        return ""

    # 1. Strip common whitespace to see if it looks like a b64 block
    cleaned = text.strip().replace("\r", "").replace("\n", "").replace(" ", "")
    
    # If it's too short, it's probably just short text, or irrelevant.
    if len(cleaned) < 20: 
        return text

    # 2. Aggressive Try-Decode
    try:
        decoded_bytes = base64.b64decode(cleaned, validate=False)
        
        # 3. Check if the result is valid UTF-8 Text
        try:
            decoded_text = decoded_bytes.decode("utf-8")
        except UnicodeDecodeError:
            try:
                decoded_text = decoded_bytes.decode("latin-1")
            except:
                return text

        # 4. Heuristic: Is it readable text?
        printable_count = sum(1 for c in decoded_text if c.isprintable() or c in "\r\n\t")
        if len(decoded_text) > 0 and (printable_count / len(decoded_text)) > 0.90:
             # Success! But... is THIS text also base64? (Recursion)
             # "PGh0..." -> "<html>..."
             return _force_base64_if_needed(decoded_text, depth + 1)
        
        return text

    except Exception:
        return text

def _extract_part_payload(part) -> str:
    """Safely extract and decode payload from a message part."""
    # 1. Try standard email parsing
    try:
        content = part.get_content()
        if isinstance(content, str):
            return content
        if isinstance(content, bytes):
            return _decode_bytes(content, part.get_content_charset())
    except Exception:
        pass
    
    # 2. Raw payload fallback
    payload = part.get_payload(decode=True)
    if payload is None:
        payload = part.get_payload(decode=False)
        if isinstance(payload, list):
            return "" 
        if isinstance(payload, str):
             return payload
    
    if isinstance(payload, bytes):
        return _decode_bytes(payload, part.get_content_charset())
        
    return str(payload) if payload else ""

def _replace_cid_images(html: str, attachments: List[AttachmentInfo]) -> str:
    """
    Replace src="cid:xyz" with src="data:image/...;base64,..."
    so images render inline in the QTextBrowser.
    """
    if not html or not attachments:
        return html
        
    for att in attachments:
        if not att.content_id:
            continue
            
        # CID usually comes as <foo@bar.com>, we need to strip brackets
        clean_cid = att.content_id.strip("<>")
        
        if f"cid:{clean_cid}" in html:
            try:
                # Convert bytes to base64 string
                b64_img = base64.b64encode(att.payload).decode('ascii')
                data_uri = f"data:{att.content_type};base64,{b64_img}"
                html = html.replace(f"cid:{clean_cid}", data_uri)
            except Exception:
                pass
                
    return html

def _recursive_extract(msg) -> Tuple[List[str], List[str], List[AttachmentInfo]]:
    text_parts = []
    html_parts = []
    attachments = []

    if msg.is_multipart():
        for part in msg.walk():
            # If the part is itself multipart, walk() visits children, skipping container
            if part.get_content_maintype() == 'multipart':
                continue

            fname = part.get_filename()
            disp = (part.get_content_disposition() or "").lower()
            ctype = part.get_content_type()
            cid = part.get("Content-ID")

            is_attachment = (disp == 'attachment') or (fname is not None) or (cid is not None and "image" in ctype)

            if is_attachment:
                # Capture attachment info
                payload_bytes = part.get_payload(decode=True)
                if not payload_bytes: 
                    # Try raw if decode fail
                    raw = part.get_payload(decode=False)
                    if isinstance(raw, str): payload_bytes = raw.encode()
                    else: payload_bytes = b""
                
                attachments.append(AttachmentInfo(
                    filename=fname or "unknown",
                    content_type=ctype,
                    size_bytes=len(payload_bytes or b""),
                    content_id=cid,
                    payload=payload_bytes or b""
                ))
                
                # If it's an inline image, we usually DON'T want it as separate text body
                # But we do keep it in attachments list for CID replacement
                continue
            
            # Not an attachment -> Body candidate
            payload = _extract_part_payload(part)
            
            # Recursive Heuristic for hidden Base64
            payload = _force_base64_if_needed(payload)

            if ctype == "text/plain":
                if payload.strip(): text_parts.append(payload)
            elif ctype == "text/html":
                if payload.strip(): html_parts.append(payload)
            elif part.get_content_maintype() == 'text':
                if payload.strip(): text_parts.append(payload)
    else:
        # Not multipart
        payload = _extract_part_payload(msg)
        payload = _force_base64_if_needed(payload)
        ctype = msg.get_content_type()
        
        if ctype == "text/html":
            html_parts.append(payload)
        else:
            text_parts.append(payload)

    return text_parts, html_parts, attachments

def parse_eml(path: str | Path) -> ParsedEML:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"File not found: {p}")

    raw_bytes = p.read_bytes()
    
    # ---------------------------------------------------
    # FIX: Detect if the ENTIRE file is Base64 encoded.
    # Some email exports (like forwarded messages from web clients)
    # wrap the whole EML in Base64 without headers.
    # ---------------------------------------------------
    try:
        # Quick heuristic: if first 100 characters are valid Base64 chars only
        sample = raw_bytes[:200].decode('ascii', errors='ignore')
        cleaned = sample.replace('\r', '').replace('\n', '').replace(' ', '')
        
        import re
        if re.fullmatch(r'[A-Za-z0-9+/=]+', cleaned):
            # Likely entire file is Base64. Try decoding.
            full_cleaned = raw_bytes.decode('ascii', errors='ignore').replace('\r', '').replace('\n', '').replace(' ', '')
            try:
                decoded_bytes = base64.b64decode(full_cleaned, validate=True)
                # Check if decoded looks like valid EML (should start with headers like "From:", "Received:", etc.)
                head_text = decoded_bytes[:100].decode('utf-8', errors='ignore')
                if any(h in head_text for h in ['From:', 'Subject:', 'Received:', 'Date:', 'MIME-Version:']):
                    # SUCCESS! Use decoded bytes as the real EML
                    raw_bytes = decoded_bytes
            except Exception:
                pass # Not valid Base64, proceed with original
    except Exception:
        pass

    msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)

    # Headers
    headers_raw_lines = []
    headers = {}
    for k, v in msg.items():
        headers[k] = str(v)
        headers_raw_lines.append(f"{k}: {v}")
    headers_raw = "\n".join(headers_raw_lines)

    # Body extraction
    text_parts, html_parts, attachments = _recursive_extract(msg)

    final_text = "\n" + ("-"*40) + "\n".join(text_parts).strip()
    
    # CID Replacement
    combined_html = "<br><hr><br>".join(html_parts).strip()
    final_html = _replace_cid_images(combined_html, attachments)

    return ParsedEML(
        path=p,
        headers_raw=headers_raw,
        headers=headers,
        subject=_safe_get(msg, "Subject"),
        from_=_safe_get(msg, "From"),
        to=_safe_get(msg, "To"),
        date=_safe_get(msg, "Date"),
        text_body=final_text.strip(),
        html_body=final_html,
        attachments=attachments,
    )
