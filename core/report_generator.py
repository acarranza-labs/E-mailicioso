# -*- coding: utf-8 -*-
"""
Report Generator Module.
Generate HTML forensic reports from parsed emails.
"""
from __future__ import annotations

from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any
import html


def generate_html_report(
    parsed_eml,
    auth_results: List = None,
    iocs = None,
    url_analysis: List[Dict] = None,
    output_path: Path = None
) -> str:
    """
    Generate a comprehensive HTML forensic report.
    
    Returns the HTML string. If output_path is provided, also saves to file.
    """
    
    # Escape helper
    def esc(s):
        return html.escape(str(s)) if s else ""
    
    # Build sections
    header_section = f"""
    <div class="section">
        <h2>📨 Email Metadata</h2>
        <table>
            <tr><th>Subject</th><td>{esc(parsed_eml.subject)}</td></tr>
            <tr><th>From</th><td>{esc(parsed_eml.from_)}</td></tr>
            <tr><th>To</th><td>{esc(parsed_eml.to)}</td></tr>
            <tr><th>Date</th><td>{esc(parsed_eml.date)}</td></tr>
            <tr><th>Source File</th><td>{esc(parsed_eml.path)}</td></tr>
        </table>
    </div>
    """
    
    # Authentication Results
    auth_section = ""
    if auth_results:
        auth_rows = ""
        for ar in auth_results:
            status_class = "pass" if ar.result == "pass" else "fail"
            auth_rows += f"""
            <tr>
                <td><strong>{esc(ar.mechanism)}</strong></td>
                <td class="{status_class}">{esc(ar.result.upper())}</td>
                <td>{esc(ar.details)}</td>
            </tr>
            """
        auth_section = f"""
        <div class="section">
            <h2>🛡️ Authentication Results</h2>
            <table>
                <tr><th>Mechanism</th><th>Result</th><th>Details</th></tr>
                {auth_rows}
            </table>
        </div>
        """
    
    # IOCs
    ioc_section = ""
    if iocs:
        ip_list = "<li>" + "</li><li>".join(esc(ip) for ip in iocs.ips) + "</li>" if iocs.ips else "<li>None found</li>"
        domain_list = "<li>" + "</li><li>".join(esc(d) for d in iocs.domains) + "</li>" if iocs.domains else "<li>None found</li>"
        
        hash_rows = ""
        for h in iocs.attachment_hashes:
            hash_rows += f"""
            <tr>
                <td>{esc(h.get('filename', 'N/A'))}</td>
                <td><code>{esc(h.get('md5', 'N/A'))}</code></td>
                <td><code>{esc(h.get('sha256', 'N/A'))}</code></td>
            </tr>
            """
        
        ioc_section = f"""
        <div class="section">
            <h2>🧲 Indicators of Compromise</h2>
            <h3>IP Addresses</h3>
            <ul>{ip_list}</ul>
            <h3>Domains</h3>
            <ul>{domain_list}</ul>
            <h3>Attachment Hashes</h3>
            <table>
                <tr><th>Filename</th><th>MD5</th><th>SHA256</th></tr>
                {hash_rows if hash_rows else "<tr><td colspan='3'>No attachments</td></tr>"}
            </table>
        </div>
        """
    
    # URLs
    url_section = ""
    if url_analysis:
        url_rows = ""
        for ua in url_analysis:
            obf_badge = '<span class="badge warning">⚠️ Obfuscated</span>' if ua.get('is_obfuscated') else ''
            url_rows += f"""
            <tr>
                <td>{esc(ua.get('original', ''))}</td>
                <td>{esc(ua.get('final', ''))}</td>
                <td>{obf_badge}</td>
            </tr>
            """
        url_section = f"""
        <div class="section">
            <h2>🔗 URL Analysis</h2>
            <table>
                <tr><th>Original URL</th><th>Final Destination</th><th>Status</th></tr>
                {url_rows}
            </table>
        </div>
        """
    
    # Attachments
    att_section = ""
    if parsed_eml.attachments:
        att_rows = ""
        for att in parsed_eml.attachments:
            att_rows += f"""
            <tr>
                <td>{esc(att.filename)}</td>
                <td>{esc(att.content_type)}</td>
                <td>{att.size_bytes / 1024:.1f} KB</td>
            </tr>
            """
        att_section = f"""
        <div class="section">
            <h2>📎 Attachments</h2>
            <table>
                <tr><th>Filename</th><th>Type</th><th>Size</th></tr>
                {att_rows}
            </table>
        </div>
        """
    
    # Full HTML
    report_html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>E-mailicioso Forensic Report</title>
    <style>
        * {{ box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 1000px;
            margin: 0 auto;
            padding: 20px;
            background: #1a1a2e;
            color: #eee;
        }}
        h1 {{ color: #00d4ff; border-bottom: 2px solid #00d4ff; padding-bottom: 10px; }}
        h2 {{ color: #ff6b6b; margin-top: 30px; }}
        .section {{
            background: #16213e;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 10px 0;
        }}
        th, td {{
            text-align: left;
            padding: 10px;
            border-bottom: 1px solid #333;
        }}
        th {{ background: #0f3460; }}
        .pass {{ color: #00ff88; font-weight: bold; }}
        .fail {{ color: #ff4444; font-weight: bold; }}
        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 12px;
        }}
        .badge.warning {{ background: #ff9800; color: #000; }}
        code {{
            background: #0f3460;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 11px;
            word-break: break-all;
        }}
        ul {{ margin: 5px 0; padding-left: 20px; }}
        .footer {{
            text-align: center;
            color: #666;
            margin-top: 40px;
            font-size: 12px;
        }}
    </style>
</head>
<body>
    <h1>📧 E-mailicioso Forensic Report</h1>
    <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    
    {header_section}
    {auth_section}
    {ioc_section}
    {url_section}
    {att_section}
    
    <div class="section">
        <h2>📝 Raw Headers</h2>
        <pre style="background:#0f3460; padding:15px; overflow-x:auto; font-size:11px;">{esc(parsed_eml.headers_raw)}</pre>
    </div>
    
    <div class="footer">
        <p>Generated by E-mailicioso Forensic Toolkit</p>
    </div>
</body>
</html>
    """
    
    if output_path:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(report_html, encoding='utf-8')
    
    return report_html
