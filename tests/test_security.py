from modules.security_checker import analyze_security_headers, calculate_risk


def test_all_headers_present():
    headers = {
        "strict-transport-security": "max-age=31536000",
        "x-content-type-options": "nosniff",
        "content-security-policy": "default-src 'self'",
        "referrer-policy": "no-referrer",
    }
    findings = analyze_security_headers(headers)
    assert len(findings) == 4
    assert all(f["status"] == "PRESENT" for f in findings)
    assert all(f["severity"] == "INFO" for f in findings)


def test_no_headers_present():
    findings = analyze_security_headers({})
    assert len(findings) == 4
    assert all(f["status"] == "NOT DETECTED" for f in findings)

    hsts_finding = next(f for f in findings if f["name"] == "HSTS")
    assert hsts_finding["severity"] == "LOW"


def test_risk_all_info():
    findings = analyze_security_headers({
        "strict-transport-security": "max-age=31536000",
        "x-content-type-options": "nosniff",
        "content-security-policy": "default-src 'self'",
        "referrer-policy": "no-referrer",
    })
    risk = calculate_risk(findings)
    assert risk["overall"] == "INFO"
    assert risk["high"] == 0
    assert risk["medium"] == 0
    assert risk["low"] == 0


def test_risk_escalates_to_low_without_hsts():
    findings = analyze_security_headers({})
    risk = calculate_risk(findings)
    assert risk["overall"] == "LOW"
    assert risk["low"] == 1


def test_risk_empty_findings():
    risk = calculate_risk([])
    assert risk["overall"] == "INFO"
    assert risk["high"] == risk["medium"] == risk["low"] == risk["info"] == 0
