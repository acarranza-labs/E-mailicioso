# -*- coding: utf-8 -*-
"""
Security Analysis Module.
- Parse Authentication-Results headers (SPF, DKIM, DMARC)
- Extract IOCs (IPs, domains, hashes)
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from pathlib import Path


@dataclass
class AuthResult:
    """Result of SPF/DKIM/DMARC check."""
    mechanism: str  # "spf", "dkim", "dmarc"
    result: str     # "pass", "fail", "neutral", "none", etc.
    details: str    # Raw detail string


@dataclass
class IOCReport:
    """Indicators of Compromise extracted from email."""
    ips: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    attachment_hashes: List[Dict[str, str]] = field(default_factory=list)  # [{filename, md5, sha256}]
    

def parse_authentication_results(headers: Dict[str, str]) -> List[AuthResult]:
    """
    Parse Authentication-Results header to extract SPF, DKIM, DMARC results.
    
    Example header:
    Authentication-Results: mx.google.com;
       dkim=pass header.i=@example.com;
       spf=pass smtp.mailfrom=example.com;
       dmarc=pass (p=REJECT) header.from=example.com
    """
    results = []
    
    # Look for Authentication-Results header (case-insensitive)
    auth_header = None
    for k, v in headers.items():
        if k.lower() == "authentication-results":
            auth_header = v
            break
    
    if not auth_header:
        return results
    
    # Parse SPF
    spf_match = re.search(r'spf=(\w+)', auth_header, re.IGNORECASE)
    if spf_match:
        results.append(AuthResult(
            mechanism="SPF",
            result=spf_match.group(1).lower(),
            details=_extract_detail(auth_header, "spf")
        ))
    
    # Parse DKIM
    dkim_match = re.search(r'dkim=(\w+)', auth_header, re.IGNORECASE)
    if dkim_match:
        results.append(AuthResult(
            mechanism="DKIM",
            result=dkim_match.group(1).lower(),
            details=_extract_detail(auth_header, "dkim")
        ))
    
    # Parse DMARC
    dmarc_match = re.search(r'dmarc=(\w+)', auth_header, re.IGNORECASE)
    if dmarc_match:
        results.append(AuthResult(
            mechanism="DMARC",
            result=dmarc_match.group(1).lower(),
            details=_extract_detail(auth_header, "dmarc")
        ))
    
    return results


def _extract_detail(header: str, mechanism: str) -> str:
    """Extract the full detail for a mechanism from the header."""
    # Find from mechanism= to next ; or end
    pattern = rf'{mechanism}=\w+[^;]*'
    match = re.search(pattern, header, re.IGNORECASE)
    return match.group(0) if match else ""


def extract_ips_from_received(headers: Dict[str, str]) -> List[str]:
    """
    Extract IP addresses from Received headers.
    These show the path the email took.
    """
    ips = []
    
    # Collect all Received headers (there can be multiple)
    received_values = []
    for k, v in headers.items():
        if k.lower() == "received":
            received_values.append(v)
    
    # Also check for headers_raw if available (multiple Received lines)
    # But for simplicity, we'll work with what we have
    
    # IPv4 and IPv6 patterns
    ipv4_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ipv6_pattern = r'\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b'
    
    for recv in received_values:
        ips.extend(re.findall(ipv4_pattern, recv))
        ips.extend(re.findall(ipv6_pattern, recv))
    
    # Deduplicate, filter out private/local IPs
    unique_ips = []
    seen = set()
    for ip in ips:
        if ip not in seen and not _is_private_ip(ip):
            seen.add(ip)
            unique_ips.append(ip)
    
    return unique_ips


def _is_private_ip(ip: str) -> bool:
    """Check if an IP is private/local (should be excluded from IOCs)."""
    private_prefixes = [
        '10.', '192.168.', '127.', '0.', '169.254.',
        '172.16.', '172.17.', '172.18.', '172.19.',
        '172.20.', '172.21.', '172.22.', '172.23.',
        '172.24.', '172.25.', '172.26.', '172.27.',
        '172.28.', '172.29.', '172.30.', '172.31.',
    ]
    return any(ip.startswith(p) for p in private_prefixes)


def calculate_attachment_hashes(attachments) -> List[Dict[str, str]]:
    """
    Calculate MD5 and SHA256 hashes for each attachment.
    `attachments` is List[AttachmentInfo] from eml_parser.
    """
    hashes = []
    for att in attachments:
        if hasattr(att, 'payload') and att.payload:
            hashes.append({
                "filename": att.filename,
                "content_type": att.content_type,
                "md5": hashlib.md5(att.payload).hexdigest(),
                "sha256": hashlib.sha256(att.payload).hexdigest(),
            })
    return hashes


def extract_iocs(parsed_eml) -> IOCReport:
    """
    Extract all IOCs from a parsed email.
    """
    report = IOCReport()
    
    # IPs from Received headers
    report.ips = extract_ips_from_received(parsed_eml.headers)
    
    # Domains from URLs (we can get these from url_extractor separately)
    # For now, just extract domain from From header
    from_header = parsed_eml.from_
    domain_match = re.search(r'@([\w.-]+)', from_header)
    if domain_match:
        report.domains.append(domain_match.group(1))
    
    # Attachment hashes
    report.attachment_hashes = calculate_attachment_hashes(parsed_eml.attachments)
    
    return report


def iocs_to_json(report: IOCReport) -> str:
    """Export IOCs to JSON string."""
    import json
    return json.dumps({
        "ips": report.ips,
        "domains": report.domains,
        "urls": report.urls,
        "attachment_hashes": report.attachment_hashes,
    }, indent=2)
