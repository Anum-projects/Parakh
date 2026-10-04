from app import scoring
from app.findings import Finding

F = lambda w, c="x": Finding(c, w, "en", "ur")
ALL_OK = {"dns": True, "page": True, "whois": True, "ssl": True}


def test_thresholds():
    assert scoring.level_for(30) == "low_risk"
    assert scoring.level_for(31) == "suspicious"
    assert scoring.level_for(65) == "suspicious"
    assert scoring.level_for(66) == "high_risk"


def test_score_clamped():
    s, lvl, *_ = scoring.compute([F(80), F(80)], ALL_OK, False, False)
    assert s == 100 and lvl == "high_risk"


def test_low_confidence_never_reports_low_risk():
    s, lvl, conf, used = scoring.compute([], {"dns": False, "page": False, "whois": False}, False, False)
    assert conf == "low" and lvl == "suspicious"
    assert any(f.code == "insufficient_data" for f in used)


def test_confidence_levels():
    assert scoring.confidence_for(ALL_OK) == "high"
    assert scoring.confidence_for({"a": True, "b": True, "c": False, "d": False}) == "medium"
    assert scoring.confidence_for({"a": True, "b": False, "c": False}) == "low"


def test_official_caps_score():
    s, lvl, *_ = scoring.compute([F(40)], ALL_OK, True, False)
    assert s <= 10 and lvl == "low_risk"


def test_blocklist_forces_high_risk_even_if_official():
    s, lvl, *_ = scoring.compute([F(80)], ALL_OK, True, True)
    assert lvl == "high_risk" and s >= 90


def test_recommendation_languages():
    assert "CNIC" in scoring.recommendation("high_risk", "high", "en")
    assert "شناختی" in scoring.recommendation("high_risk", "high", "ur")
    assert "verify further" in scoring.recommendation("suspicious", "low", "en")
