import pytest

from app.analyzers.url_analysis import InvalidURL, parse_url, url_findings


def codes(raw):
    return {f.code for f in url_findings(parse_url(raw))}


def test_adds_https_when_scheme_missing():
    p = parse_url("example.com/path")
    assert p.scheme == "https" and p.host == "example.com" and not p.had_scheme


@pytest.mark.parametrize("bad", ["", "   ", "ftp://example.com", "http://localhost", "http://", "a b.com"])
def test_invalid_urls(bad):
    with pytest.raises(InvalidURL):
        parse_url(bad)


def test_ip_host():
    assert "ip_host" in codes("http://203.0.113.5/login")


def test_shortener_and_http():
    c = codes("http://bit.ly/abc")
    assert {"shortener", "no_https"} <= c


def test_userinfo_trick():
    assert "userinfo" in codes("https://hec.gov.pk@evil.example.com/")


def test_punycode():
    assert "punycode" in codes("https://xn--pple-43d.com")


def test_suspicious_tld_and_keywords():
    c = codes("https://free-scholarship-register-now.xyz/apply")
    assert {"suspicious_tld", "scam_keywords", "many_hyphens"} <= c


def test_org_impersonation_flagged():
    assert "org_impersonation" in codes("https://hec-scholarship-2026.com/register")
    assert "org_impersonation" in codes("https://hec.example-portal.com")


def test_official_domain_not_flagged_as_impersonation():
    assert "org_impersonation" not in codes("https://www.hec.gov.pk/english/scholarships")


def test_no_false_org_match_inside_words():
    assert "org_impersonation" not in codes("https://checkout.example.com")  # contains 'hec' inside a word


def test_clean_url_has_no_findings():
    assert codes("https://www.wikipedia.org/") == set()
