import json
import subprocess
import sys

from conftest import DEMO, ROOT, build_email
from emailicioso.core import iocs as ioc_mod
from emailicioso.core import report
from emailicioso.core.analyzer import analyze_bytes
from emailicioso.core.models import Severity
from emailicioso.core.scoring import score_findings


def test_demo_sample_is_malicious(demo_result):
    r = demo_result
    assert r.level == Severity.CRITICAL
    assert r.score >= 80
    t = {f.title for f in r.findings}
    for expected in ("DMARC failed", "Link text does not match the real destination",
                     "Reply-To sends answers to a different domain",
                     "Microsoft Defender classified it as Phishing",
                     "HTML form posts data from inside the email"):
        assert expected in t
    assert r.originating_ip == "198.51.100.23"
    assert r.network_message_id == "7f3c2a10-5d4e-4b8a-9c21-08ddf1a2b3c4"


def test_demo_iocs_exclude_legit_infrastructure(demo_result):
    i = demo_result.iocs
    assert "login-rnicrosoftonline.web.app" in i.domains
    assert "rnicrosoft-alerts.com" in i.domains
    assert not any("microsoft.com" == d or d.endswith(".microsoft.com") for d in i.domains)
    assert "bit.ly" not in i.domains
    assert not any("safelinks" in u for u in i.urls)
    assert "j.garcia@contoso.com" not in i.emails


def test_benign_email_is_low():
    raw = build_email(
        from_="Ana <ana@example.org>", subject="Lunch on Friday?",
        text="Hi Bob, are we still on for lunch on Friday? Cheers, Ana",
        headers=[("Authentication-Results", "mx.contoso.com; spf=pass smtp.mailfrom=example.org; "
                                            "dkim=pass header.d=example.org; dmarc=pass header.from=example.org")],
    )
    r = analyze_bytes(raw)
    assert r.level <= Severity.LOW
    assert r.score < 8


def test_scoring_caps_low_findings():
    from emailicioso.core.models import Finding

    lows = [Finding(Severity.LOW, "URL", f"low {i}") for i in range(20)]
    score, level = score_findings(lows)
    assert score == 20 and level == Severity.LOW
    score, level = score_findings([Finding(Severity.CRITICAL, "Attachment", "exe")])
    assert level == Severity.CRITICAL


def test_hunting_queries_use_identifiers(demo_result):
    text = "\n".join(q.query for q in demo_result.hunting)
    assert 'NetworkMessageId == "7f3c2a10-5d4e-4b8a-9c21-08ddf1a2b3c4"' in text
    assert '"login-rnicrosoftonline.web.app"' in text
    assert "ago(30d)" in text
    assert all(q.query.count("(") == q.query.count(")") for q in demo_result.hunting)


def test_kql_string_escaping():
    from emailicioso.core.hunting import kql_string

    assert kql_string('say "hi" \\ bye') == '"say \\"hi\\" \\\\ bye"'


def test_json_export_is_serializable(demo_result):
    data = json.loads(report.to_json(demo_result))
    assert data["verdict"]["level"] == "Critical"
    assert data["message"]["sha256"] == demo_result.email.sha256
    assert data["iocs"]["hashes"]


def test_html_report_escapes_content():
    raw = build_email(subject='<script>alert("x")</script>', text="hi")
    page = report.html_report(analyze_bytes(raw))
    assert "<script>alert" not in page
    assert "&lt;script&gt;alert" in page


def test_ticket_summary_languages(demo_result):
    en = report.summary_text(demo_result, "en")
    es = report.summary_text(demo_result, "es")
    assert "Verdict: MALICIOUS" in en and "Recommended actions" in en
    assert "Veredicto: MALICIOSO" in es and "Acciones recomendadas" in es
    assert "rnicrosoft-alerts[.]com" in en  # defanged


def test_ioc_exports(demo_result):
    csv_text = ioc_mod.to_csv(demo_result.iocs, defanged=True)
    assert csv_text.startswith("type,value,context")
    assert "domain,rnicrosoft-alerts[.]com," in csv_text
    assert json.loads(ioc_mod.to_json(demo_result.iocs))["ips"]


def test_cli_analyze_text_and_fail_on():
    cmd = [sys.executable, "-m", "emailicioso", "analyze", str(DEMO), "--no-color"]
    out = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert "[MALICIOUS]" in out.stdout
    out = subprocess.run(cmd + ["--fail-on", "high", "-f", "json"], cwd=ROOT, capture_output=True, text=True)
    assert out.returncode == 2
    assert json.loads(out.stdout)["verdict"]["label"] == "Malicious"


def test_cli_writes_html(tmp_path):
    target = tmp_path / "r.html"
    out = subprocess.run([sys.executable, "-m", "emailicioso", "analyze", str(DEMO), "-f", "summary",
                          "--lang", "es", "--html", str(target)], cwd=ROOT, capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert "Veredicto" in out.stdout
    assert target.read_text(encoding="utf-8").startswith("<!DOCTYPE html>")


def test_cli_missing_file():
    out = subprocess.run([sys.executable, "-m", "emailicioso", "analyze", "nope.eml"], cwd=ROOT,
                         capture_output=True, text=True)
    assert out.returncode == 1
    assert "nope.eml" in out.stderr
