"""Static attachment triage: hashes, real file type, risky traits. Nothing is executed."""

from __future__ import annotations

import hashlib
import io
import re
import zipfile

from emailicioso.core.models import AttachmentInfo, Finding, Severity

EXECUTABLE_EXT = {
    "exe", "scr", "com", "pif", "msi", "msp", "bat", "cmd", "js", "jse", "vbs", "vbe", "wsf",
    "wsh", "hta", "ps1", "psm1", "lnk", "cpl", "dll", "jar", "reg", "inf", "scf", "url", "msc",
    "gadget", "application", "appref-ms", "msix", "appx", "appxbundle", "chm", "xll", "xlam",
    "ppam", "wiz", "sct", "iqy", "slk", "settingcontent-ms", "library-ms", "search-ms", "py",
    "sh", "apk",
}
CONTAINER_EXT = {"iso", "img", "vhd", "vhdx", "zip", "rar", "7z", "gz", "tgz", "cab", "ace", "arj",
                 "tar", "xz", "bz2", "z", "uue", "lzh"}
MACRO_EXT = {"docm", "dotm", "xlsm", "xltm", "xlsb", "pptm", "potm", "ppsm", "sldm"}
HTML_EXT = {"html", "htm", "shtml", "xhtml", "svg", "mht", "mhtml"}
DOC_EXT = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "rtf", "odt", "txt", "csv", "jpg",
           "jpeg", "png", "gif", "bmp"}

RLO = "‮"

SMUGGLING_PATTERNS = [
    (re.compile(rb"atob\s*\(", re.I), "base64 decoding in script (atob)"),
    (re.compile(rb"new\s+Blob\s*\(", re.I), "builds a file in the browser (Blob)"),
    (re.compile(rb"msSaveOrOpenBlob|createObjectURL", re.I), "triggers a download from script"),
    (re.compile(rb"\.download\s*=", re.I), "forces a file download"),
    (re.compile(rb"<input[^>]+type\s*=\s*['\"]?password", re.I), "contains a password field"),
    (re.compile(rb"<form[^>]+action\s*=", re.I), "contains a form that submits data"),
    (re.compile(rb"window\.location|location\.(href|replace)\s*[=(]|http-equiv\s*=\s*['\"]?refresh", re.I),
     "redirects the browser"),
    (re.compile(rb"eval\s*\(|unescape\s*\(|String\.fromCharCode", re.I), "obfuscated JavaScript"),
    (re.compile(rb"api\.telegram\.org|discord(app)?\.com/api/webhooks", re.I),
     "exfiltrates to Telegram/Discord"),
]


def _ext(name: str) -> str:
    name = name.lower().strip().rstrip(". ")
    return name.rsplit(".", 1)[-1] if "." in name else ""


def sniff_type(data: bytes, filename: str = "") -> str:
    """Identify the real file type from magic bytes (best effort, no dependencies)."""
    head = data[:16]
    if not data:
        return "empty"
    if head.startswith(b"MZ"):
        return "Windows executable (PE)"
    if head.startswith(b"\x7fELF"):
        return "Linux executable (ELF)"
    if head[:4] in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe"):
        return "macOS executable (Mach-O)"
    if head.startswith(b"%PDF"):
        return "PDF document"
    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        if b"__substg1.0_" in data[:65536] or _ext(filename) == "msg":
            return "Outlook message (MSG)"
        return "OLE compound file (legacy Office)"
    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06"):
        return _sniff_zip(data)
    if head.startswith(b"Rar!\x1a\x07"):
        return "RAR archive"
    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7-Zip archive"
    if head.startswith(b"\x1f\x8b"):
        return "GZIP archive"
    if head.startswith(b"MSCF"):
        return "Cabinet archive (CAB)"
    if len(data) > 0x8006 and data[0x8001:0x8006] == b"CD001":
        return "ISO disk image"
    if head.startswith(b"conectix") or data[-512:-504] == b"conectix":
        return "VHD disk image"
    if head.startswith(b"vhdxfile"):
        return "VHDX disk image"
    if head.startswith(b"L\x00\x00\x00\x01\x14\x02\x00"):
        return "Windows shortcut (LNK)"
    if head.startswith(b"\xe4\x52\x5c\x7b\x8c\xd8\xa7\x4d"):
        return "OneNote document"
    if head.startswith(b"{\\rt"):
        return "RTF document"
    if head.startswith(b"\x89PNG"):
        return "PNG image"
    if head.startswith(b"\xff\xd8\xff"):
        return "JPEG image"
    if head.startswith((b"GIF87a", b"GIF89a")):
        return "GIF image"
    if head.startswith(b"BM"):
        return "BMP image"
    if head[:4] in (b"II*\x00", b"MM\x00*"):
        return "TIFF image"
    if head[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "WEBP image"
    text = data[:4096].lstrip(b"\xef\xbb\xbf \t\r\n").lower()
    if text.startswith(b"<svg") or (text.startswith(b"<?xml") and b"<svg" in text):
        return "SVG image"
    if text.startswith((b"<!doctype html", b"<html", b"<head", b"<body", b"<script", b"<meta", b"<div")) or (
        b"<html" in text and b"</" in text
    ):
        return "HTML document"
    if text.startswith(b"begin:vcalendar"):
        return "iCalendar invite"
    if text.startswith(b"<?xml"):
        return "XML document"
    if _looks_text(data[:4096]):
        return "Text"
    return "Unknown binary"


def _looks_text(chunk: bytes) -> bool:
    if not chunk:
        return False
    try:
        chunk.decode("utf-8")
        return b"\x00" not in chunk
    except UnicodeDecodeError:
        return sum(32 <= b < 127 or b in (9, 10, 13) for b in chunk) / len(chunk) > 0.9


def _sniff_zip(data: bytes) -> str:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = zf.namelist()
    except (zipfile.BadZipFile, ValueError, RuntimeError, NotImplementedError):
        return "ZIP archive (corrupt)"
    lower = [n.lower() for n in names]
    if "[content_types].xml" in lower:
        if any(n.startswith("word/") for n in lower):
            return "Word document (OOXML)"
        if any(n.startswith("xl/") for n in lower):
            return "Excel workbook (OOXML)"
        if any(n.startswith("ppt/") for n in lower):
            return "PowerPoint presentation (OOXML)"
        return "Office Open XML document"
    if "meta-inf/manifest.mf" in lower or any(n.endswith(".class") for n in lower):
        return "Java archive (JAR)"
    if "mimetype" in lower and any(n.startswith("content.xml") for n in lower):
        return "OpenDocument file"
    if "androidmanifest.xml" in lower:
        return "Android package (APK)"
    return "ZIP archive"


def _zip_traits(data: bytes) -> list[tuple[Severity, str]]:
    traits: list[tuple[Severity, str]] = []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            infos = zf.infolist()
    except (zipfile.BadZipFile, ValueError, RuntimeError, NotImplementedError):
        return traits
    names = [i.filename for i in infos]
    lower = [n.lower() for n in names]
    if any(i.flag_bits & 0x1 for i in infos):
        traits.append((Severity.HIGH, "Password-protected archive (content hidden from scanners)"))
    if any(n.endswith("vbaproject.bin") for n in lower):
        traits.append((Severity.HIGH, "Contains VBA macros"))
    if any(n.endswith(".bin") and "activex" in n for n in lower):
        traits.append((Severity.MEDIUM, "Contains ActiveX controls"))
    risky = [n for n in names if _ext(n) in EXECUTABLE_EXT or _ext(n) in HTML_EXT - {"svg"}
             or _ext(n) in {"iso", "img", "vhd", "vhdx", "one"}]
    if risky and "[content_types].xml" not in lower:
        traits.append((Severity.HIGH, "Archive contains risky files: " + ", ".join(risky[:5])))
    nested = [n for n in names if _ext(n) in CONTAINER_EXT]
    if nested:
        traits.append((Severity.LOW, "Nested archive: " + ", ".join(nested[:3])))
    if "[content_types].xml" in lower:
        rels = []
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                for n in names:
                    if n.lower().endswith(".rels") and zf.getinfo(n).file_size < 2_000_000:
                        rels.append(zf.read(n))
        except Exception:
            rels = []
        blob = b"\n".join(rels)
        if re.search(rb'TargetMode="External"', blob) and re.search(rb"attachedTemplate|oleObject|frame", blob, re.I):
            traits.append((Severity.HIGH, "Loads a remote template/object (template injection)"))
    return traits


def _pdf_traits(data: bytes) -> list[tuple[Severity, str]]:
    traits: list[tuple[Severity, str]] = []
    if re.search(rb"/(JavaScript|JS)\b", data):
        traits.append((Severity.HIGH, "PDF contains JavaScript"))
    if re.search(rb"/Launch\b", data):
        traits.append((Severity.HIGH, "PDF has a /Launch action"))
    if re.search(rb"/EmbeddedFile\b", data):
        traits.append((Severity.MEDIUM, "PDF embeds files"))
    if re.search(rb"/OpenAction\b|/AA\b", data):
        traits.append((Severity.LOW, "PDF runs an action when opened"))
    if re.search(rb"/AcroForm\b", data) and re.search(rb"/SubmitForm\b", data):
        traits.append((Severity.MEDIUM, "PDF form submits data to a remote server"))
    uris = len(re.findall(rb"/URI\s*\(", data))
    if uris:
        traits.append((Severity.INFO, f"PDF has {uris} link(s)"))
    return traits


def _html_traits(data: bytes, is_svg: bool) -> list[tuple[Severity, str]]:
    traits: list[tuple[Severity, str]] = []
    hits = [label for regex, label in SMUGGLING_PATTERNS if regex.search(data)]
    if is_svg and re.search(rb"<script|onload\s*=|<foreignObject", data, re.I):
        traits.append((Severity.HIGH, "SVG with active content (script/foreignObject)"))
    blob = any(h.startswith(("builds a file", "triggers a download")) for h in hits)
    if blob and any(h.startswith("base64") for h in hits):
        traits.append((Severity.HIGH, "HTML smuggling pattern (decodes and drops a file)"))
    if "contains a password field" in hits:
        traits.append((Severity.HIGH, "Local credential-harvesting page (password field)"))
    for h in hits:
        if h in ("contains a password field",):
            continue
        traits.append((Severity.MEDIUM if h in ("obfuscated JavaScript", "exfiltrates to Telegram/Discord")
                       else Severity.LOW, f"HTML {h}"))
    big_b64 = re.search(rb"[A-Za-z0-9+/]{4000,}={0,2}", data)
    if big_b64:
        traits.append((Severity.MEDIUM, "Large embedded base64 blob"))
    return traits


def _ole_traits(data: bytes) -> list[tuple[Severity, str]]:
    traits = []
    if b"_VBA_PROJECT" in data or b"V\x00B\x00A\x00" in data or b"VBA\x00" in data:
        traits.append((Severity.HIGH, "Legacy Office document with VBA macros"))
    if b"Equation.3" in data or b"E\x00q\x00u\x00a\x00t\x00i\x00o\x00n\x00" in data:
        traits.append((Severity.HIGH, "Equation Editor object (CVE-2017-11882 family)"))
    return traits


def _rtf_traits(data: bytes) -> list[tuple[Severity, str]]:
    traits = []
    if re.search(rb"\\objdata|\\objupdate|\\objocx|\\objautlink", data, re.I):
        traits.append((Severity.HIGH, "RTF with embedded OLE object (exploit vector)"))
    return traits


def analyze_attachment(att: AttachmentInfo) -> AttachmentInfo:
    data = att.payload or b""
    att.size = len(data)
    att.md5 = hashlib.md5(data).hexdigest() if data else ""
    att.sha1 = hashlib.sha1(data).hexdigest() if data else ""
    att.sha256 = hashlib.sha256(data).hexdigest() if data else ""
    att.detected_type = sniff_type(data, att.filename)

    traits: list[tuple[Severity, str]] = []
    name = att.filename or ""
    ext = _ext(name)
    dtype = att.detected_type

    if RLO in name:
        traits.append((Severity.HIGH, "Right-to-left override character hides the real extension"))
    parts = name.lower().replace(RLO, "").split(".")
    if len(parts) >= 3 and parts[-2] in DOC_EXT and (parts[-1] in EXECUTABLE_EXT or parts[-1] in CONTAINER_EXT):
        traits.append((Severity.HIGH, f"Double extension (.{parts[-2]}.{parts[-1]})"))
    if re.search(r"\s{5,}\.\w+$", name):
        traits.append((Severity.MEDIUM, "Extension pushed out of view with spaces"))
    if ext in EXECUTABLE_EXT or dtype.startswith(("Windows executable", "Linux executable", "macOS executable",
                                                    "Windows shortcut", "Java archive")):
        traits.append((Severity.CRITICAL if dtype.startswith("Windows executable") or ext in
                       ("exe", "scr", "js", "vbs", "hta", "lnk", "wsf", "bat", "cmd", "ps1") else Severity.HIGH,
                       f"Executable or script file ({dtype if ext not in EXECUTABLE_EXT else '.' + ext})"))
    if ext in {"iso", "img", "vhd", "vhdx"} or dtype.endswith("disk image"):
        traits.append((Severity.HIGH, "Disk image (used to bypass Mark-of-the-Web)"))
    if ext == "one" or dtype == "OneNote document":
        traits.append((Severity.HIGH, "OneNote document (common malware delivery in 2023+)"))
    if ext in MACRO_EXT:
        traits.append((Severity.HIGH, f"Macro-enabled Office file (.{ext})"))
    if ext in HTML_EXT or dtype in ("HTML document", "SVG image"):
        traits.append((Severity.MEDIUM, "HTML/SVG attachment (opens in the browser, often a phishing page)"))
        traits.extend(_html_traits(data, dtype == "SVG image" or ext == "svg"))
    if dtype.startswith("ZIP") or "(OOXML)" in dtype or dtype == "Office Open XML document" or dtype.startswith("Java"):
        traits.extend(_zip_traits(data))
    elif dtype in ("RAR archive", "7-Zip archive", "GZIP archive", "Cabinet archive (CAB)"):
        traits.append((Severity.LOW, f"{dtype} (contents not inspected)"))
    if dtype == "PDF document":
        traits.extend(_pdf_traits(data))
    if dtype.startswith("OLE compound"):
        traits.extend(_ole_traits(data))
    if dtype == "RTF document":
        traits.extend(_rtf_traits(data))
    if dtype == "iCalendar invite":
        traits.append((Severity.INFO, "Calendar invite (check the links in its description)"))

    mismatch = _type_mismatch(ext, dtype)
    if mismatch:
        traits.append((Severity.HIGH if "executable" in dtype.lower() else Severity.MEDIUM, mismatch))
    if att.is_email:
        traits.append((Severity.INFO, "Attached email: open it to analyze the original message"))

    seen: set[str] = set()
    uniq = []
    for sev, label in traits:
        if label not in seen:
            seen.add(label)
            uniq.append((sev, label))
    att.flags = [label for _s, label in uniq]
    att.severity = max((s for s, _l in uniq), default=Severity.INFO)
    if att.is_inline and att.severity <= Severity.INFO and dtype.endswith("image"):
        att.flags.append("Inline image")
    return att


_EXT_FAMILY = {
    "pdf": ("PDF",), "docx": ("Word",), "xlsx": ("Excel",), "pptx": ("PowerPoint",),
    "docm": ("Word",), "xlsm": ("Excel",), "pptm": ("PowerPoint",),
    "doc": ("OLE",), "xls": ("OLE",), "ppt": ("OLE",), "msg": ("Outlook", "OLE"),
    "zip": ("ZIP", "Word", "Excel", "PowerPoint", "Office", "Java", "OpenDocument"),
    "jpg": ("JPEG",), "jpeg": ("JPEG",), "png": ("PNG",), "gif": ("GIF",),
    "rtf": ("RTF",), "html": ("HTML",), "htm": ("HTML",), "svg": ("SVG",),
    "txt": ("Text",), "csv": ("Text",),
}


def _type_mismatch(ext: str, dtype: str) -> str:
    families = _EXT_FAMILY.get(ext)
    if not families or dtype in ("empty", "Unknown binary"):
        return ""
    if dtype.startswith(families) or any(f in dtype for f in families):
        return ""
    if ext in ("txt", "csv") and dtype in ("HTML document", "XML document"):
        return ""
    return f"Extension .{ext} does not match real content ({dtype})"


def attachment_findings(attachments: list[AttachmentInfo]) -> list[Finding]:
    findings = []
    for att in attachments:
        if att.severity < Severity.LOW:
            continue
        serious = [f for f in att.flags if f != "Inline image"]
        findings.append(
            Finding(
                att.severity,
                "Attachment",
                f"Risky attachment: {att.filename}",
                "; ".join(serious),
                [f"SHA256 {att.sha256}", f"Type: {att.detected_type}"],
            )
        )
    emails = [a for a in attachments if a.is_email]
    if emails:
        findings.append(
            Finding(
                Severity.INFO,
                "Attachment",
                "Contains an attached email",
                "This looks like a forwarded/reported message. The original phish is probably the "
                "attached email: open it from the Attachments tab to analyze it.",
                [a.filename for a in emails],
            )
        )
    return findings
