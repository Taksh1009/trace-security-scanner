"""
TRACE — Security Header Analysis & Risk Engine
=================================================
Evaluates common security-relevant response headers and converts
the observations into evidence-based findings, each with severity,
evidence, impact, and a recommendation. Also aggregates findings
into an overall risk level.
"""

_HEADER_SPECS = [
    {
        "header": "strict-transport-security",
        "name": "HSTS",
        "present_severity": "INFO",
        "absent_severity": "LOW",
        "present_impact": "The server provides an HSTS policy for supporting browsers.",
        "absent_impact": "The response does not provide an HSTS policy to browsers.",
        "recommendation_present": "No action required based on this passive check.",
        "recommendation_absent": "Consider enabling HSTS after validating HTTPS configuration.",
    },
    {
        "header": "x-content-type-options",
        "name": "X-Content-Type-Options",
        "present_severity": "INFO",
        "absent_severity": "INFO",
        "present_impact": "The response provides a content-type handling policy.",
        "absent_impact": "No explicit MIME-sniffing protection was observed.",
        "recommendation_present": "No action required based on this passive check.",
        "recommendation_absent": "Consider using X-Content-Type-Options: nosniff.",
    },
    {
        "header": "content-security-policy",
        "name": "Content-Security-Policy",
        "present_severity": "INFO",
        "absent_severity": "INFO",
        "present_impact": "The response provides a policy controlling content sources.",
        "absent_impact": "No Content Security Policy was observed.",
        "recommendation_present": "Review the policy periodically and keep it appropriately restrictive.",
        "recommendation_absent": "Consider deploying an appropriate Content Security Policy.",
    },
    {
        "header": "referrer-policy",
        "name": "Referrer-Policy",
        "present_severity": "INFO",
        "absent_severity": "INFO",
        "present_impact": "The response provides a policy controlling referrer information.",
        "absent_impact": "No explicit referrer-sharing policy was observed.",
        "recommendation_present": "No action required based on this passive check.",
        "recommendation_absent": "Consider configuring an appropriate Referrer-Policy.",
    },
]


def analyze_security_headers(headers: dict):
    """
    Evaluate `headers` (expects lowercase keys) against the known
    header specs and return a list of finding dicts.
    """
    findings = []

    for spec in _HEADER_SPECS:
        present = spec["header"] in headers

        findings.append({
            "name": spec["name"],
            "severity": spec["present_severity"] if present else spec["absent_severity"],
            "status": "PRESENT" if present else "NOT DETECTED",
            "evidence": (
                f"{spec['header']} header detected" if present
                else f"{spec['header']} header absent"
            ),
            "impact": spec["present_impact"] if present else spec["absent_impact"],
            "recommendation": (
                spec["recommendation_present"] if present
                else spec["recommendation_absent"]
            ),
        })

    return findings


def calculate_risk(findings):
    """
    Aggregate findings into counts per severity plus an overall
    risk level (HIGH > MEDIUM > LOW > INFO).
    """
    counts = {"high": 0, "medium": 0, "low": 0, "info": 0}

    for finding in findings:
        severity = finding.get("severity", "INFO").lower()
        if severity in counts:
            counts[severity] += 1
        else:
            counts["info"] += 1

    if counts["high"] > 0:
        overall = "HIGH"
    elif counts["medium"] > 0:
        overall = "MEDIUM"
    elif counts["low"] > 0:
        overall = "LOW"
    else:
        overall = "INFO"

    return {"overall": overall, **counts}
