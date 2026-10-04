from app.analyzers.content_analysis import analyze_html, content_findings
from app.analyzers.domain_analysis import is_public_ip

SCAM_HTML = """
<html><head><title>HEC Scholarship 2026 Registration</title></head><body>
<h1>Higher Education Commission Scholarship</h1>
<p>Hurry! Only today. Pay the registration fee via Easypaisa.</p>
<form action="https://collector.example.net/save">
  <input name="cnic" placeholder="Enter CNIC"><input type="password" name="pw">
</form></body></html>"""


def test_scam_page_signals():
    info = analyze_html(SCAM_HTML, "https://hec-apply.example.com/", "example.com")
    codes = {f.code for f in content_findings(info)}
    assert {"asks_sensitive", "asks_password", "asks_payment", "urgency",
            "form_other_domain", "org_mismatch_content"} <= codes


def test_official_site_mentioning_itself_is_not_flagged():
    info = analyze_html(SCAM_HTML, "https://hec.gov.pk/", "hec.gov.pk")
    assert "org_mismatch_content" not in {f.code for f in content_findings(info)}


def test_benign_page():
    info = analyze_html("<html><title>Recipes</title><body><p>Pasta.</p></body></html>", "https://a.com/", "a.com")
    assert content_findings(info) == []


def test_ssrf_guard():
    for ip in ["127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254", "::1", "172.16.0.1"]:
        assert not is_public_ip(ip), ip
    assert is_public_ip("8.8.8.8")
