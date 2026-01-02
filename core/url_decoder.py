# -*- coding: utf-8 -*-
"""
URL Intelligence Module.
- Detect and decode obfuscated URLs (redirects, Base64 params)
"""
from __future__ import annotations

import base64
import re
from urllib.parse import urlparse, parse_qs, unquote
from typing import List, Tuple


def decode_obfuscated_url(url: str) -> Tuple[str, List[str]]:
    """
    Attempt to decode obfuscated/redirect URLs.
    
    Returns: (final_url, [intermediate_urls])
    
    Handles:
    - URL-encoded destinations (?url=https%3A%2F%2F...)
    - Base64 encoded destinations (?url=aHR0cHM6Ly8...)
    - Common redirect parameters
    """
    intermediates = []
    current_url = url
    max_depth = 5  # Prevent infinite loops
    
    redirect_params = ['url', 'redirect', 'target', 'dest', 'destination', 'goto', 'link', 'r', 'u']
    
    for _ in range(max_depth):
        try:
            parsed = urlparse(current_url)
            query = parse_qs(parsed.query)
            
            # Look for redirect parameters
            found_redirect = False
            for param in redirect_params:
                if param in query:
                    raw_value = query[param][0]
                    decoded = _try_decode(raw_value)
                    
                    if decoded and decoded.startswith(('http://', 'https://')):
                        intermediates.append(current_url)
                        current_url = decoded
                        found_redirect = True
                        break
            
            if not found_redirect:
                break
                
        except Exception:
            break
    
    return current_url, intermediates


def _try_decode(value: str) -> str:
    """Try URL decoding and Base64 decoding."""
    # First, URL decode
    decoded = unquote(value)
    
    # If it looks like a URL now, return it
    if decoded.startswith(('http://', 'https://')):
        return decoded
    
    # Try Base64
    try:
        # Clean up for Base64
        cleaned = value.replace('-', '+').replace('_', '/')
        # Pad if needed
        padding = 4 - (len(cleaned) % 4)
        if padding != 4:
            cleaned += '=' * padding
        
        b64_decoded = base64.b64decode(cleaned).decode('utf-8', errors='ignore')
        if b64_decoded.startswith(('http://', 'https://')):
            return b64_decoded
    except Exception:
        pass
    
    return decoded


def analyze_urls(urls: List[str]) -> List[dict]:
    """
    Analyze a list of URLs for obfuscation.
    
    Returns list of:
    {
        "original": str,
        "final": str,
        "is_obfuscated": bool,
        "intermediates": List[str]
    }
    """
    results = []
    for url in urls:
        final, intermediates = decode_obfuscated_url(url)
        results.append({
            "original": url,
            "final": final,
            "is_obfuscated": len(intermediates) > 0 or final != url,
            "intermediates": intermediates,
        })
    return results
