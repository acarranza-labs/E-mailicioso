def looks_blocked(status_code: int, html: str) -> bool:
    if status_code in (403, 429):
        return True

    html = html.lower()
    keywords = [
        "captcha",
        "cloudflare",
        "access denied",
        "verify you are human",
        "blocked"
    ]
    return any(k in html for k in keywords)
