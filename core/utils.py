import re
import hashlib
from urllib.parse import urlparse, unquote

def get_domain_from_url(url: str) -> str:
    try:
        parsed = urlparse(url.strip())
        host = (parsed.netloc or "").strip().lower()
        if not host:
            return "unknown-domain"
        # Manejo basico de user:pass@host
        host = host.split("@")[-1]
        host = host.split(":")[0]
        return host or "unknown-domain"
    except Exception:
        return "unknown-domain"


def url_to_safe_filename(url: str, max_len: int = 140) -> str:
    u = url.strip()
    parsed = urlparse(u)
    host = (parsed.netloc or "unknown-host").lower()
    path = unquote(parsed.path or "").strip("/")

    base = host
    if path:
        base += "_" + path.replace("/", "_")

    base = re.sub(r'[\\/:*?"<>|\x00-\x1F]+', "_", base)
    base = re.sub(r"_+", "_", base).strip("._ ")
    if not base:
        base = "capture"

    # hash para unicidad
    h = hashlib.sha1(u.encode("utf-8", errors="ignore")).hexdigest()[:8]
    
    # recortar si es muy largo
    if len(base) > max_len:
        base = base[:max_len].rstrip("._ ")

    return f"{base}__{h}.png"
