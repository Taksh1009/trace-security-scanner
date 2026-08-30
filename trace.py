"""
TRACE v3.0 — Passive Network & HTTP Security Analyzer
========================================================
Enter a domain and TRACE performs a sequence of safe, read-only
checks — DNS resolution, TCP port availability, HTTP/HTTPS response
analysis, redirect-chain inspection, TLS certificate inspection, and
security-header analysis — then reports the findings with severity,
evidence, impact, recommendations, and an overall risk level.

TRACE is a passive/observational diagnostic tool, not an exploitation
framework. It sends nothing beyond a standard GET request and a TCP
connect probe to ports the user asks it to check.
"""

from modules.input_parser import parse_target, InvalidTargetError
from modules.dns_checker import check_dns, analyze_dns
from modules.tcp_checker import check_ports, analyze_tcp, DEFAULT_PORTS
from modules.http_checker import make_request, analyze_http
from modules.redirect_checker import follow_chain, check_https_upgrade, get_status_message
from modules.tls_checker import inspect as inspect_tls
from modules.security_checker import analyze_security_headers, calculate_risk
from modules.timing import StageTimer

VERSION = "3.0"
REDIRECT_STATUSES = {301, 302, 303, 307, 308}


# ==========================================
# DISPLAY HELPERS
# ==========================================

def banner():
    print("╔══════════════════════════════════════╗")
    print(f"║              TRACE v{VERSION}               ║")
    print("║   Passive Network Security Analyzer   ║")
    print("╚══════════════════════════════════════╝")


def section(title):
    print()
    print(f"[{title}]")


def print_redirect_chain(chain):
    print("[TRANSPORT] Redirect Chain:")

    if not chain:
        print("[TRANSPORT] No redirect information available.")
        return

    for index, hop in enumerate(chain, start=1):
        status = hop["status"]
        location = hop["location"]
        scheme = hop["scheme"].upper()

        if location:
            print(f"  [{index}] {scheme} {status} → {location}")
        else:
            print(f"  [{index}] {scheme} {status} → FINAL")

    final_status = chain[-1]["status"]
    print(f"[TRANSPORT] Final Response: {final_status} {get_status_message(final_status)}")


def print_findings(findings):
    section("SECURITY FINDINGS")

    for number, finding in enumerate(findings, start=1):
        print()
        print(f"Finding #{number}: {finding['name']}")
        print(f"  Severity      : {finding['severity']}")
        print(f"  Status        : {finding['status']}")
        print(f"  Evidence      : {finding['evidence']}")
        print(f"  Impact        : {finding['impact']}")
        print(f"  Recommendation: {finding['recommendation']}")


def print_security_summary(findings, risk, tls_result):
    print()
    print("================================")
    print("       SECURITY SUMMARY")
    print("================================")
    print(f"Risk Level       : {risk['overall']}")
    print(f"High Findings    : {risk['high']}")
    print(f"Medium Findings  : {risk['medium']}")
    print(f"Low Findings     : {risk['low']}")
    print(f"Informational    : {risk['info']}")

    primary = None
    for severity in ("HIGH", "MEDIUM", "LOW"):
        for finding in findings:
            if finding["severity"] == severity:
                primary = finding
                break
        if primary:
            break
    if primary is None and findings:
        primary = findings[0]

    if primary:
        print()
        print("Primary Observation:")
        print(f"  {primary['name']} - {primary['status']}")
        print()
        print("Why it matters:")
        print(f"  {primary['impact']}")
        print()
        print("Recommended Action:")
        print(f"  {primary['recommendation']}")

    if tls_result and tls_result.get("version"):
        print()
        print("TLS Observation:")
        print(f"  {tls_result['version']} with {tls_result['cipher']}")
        print(f"  Certificate status: {tls_result['status']}")

    print()
    print("Confidence: PASSIVE / OBSERVATIONAL")
    print("================================")


def print_final_report(target_display, ip, open_ports, http_result, https_result, tls_result, risk, timer):
    print()
    print("================================")
    print("         TRACE REPORT")
    print("================================")
    print(f"Target       : {target_display}")
    print(f"IP           : {ip}")
    print(f"Open Ports   : {open_ports}")

    if http_result and http_result["status"] is not None:
        print(f"HTTP         : {http_result['status']} {http_result['reason']}")
    else:
        print("HTTP         : NOT AVAILABLE")

    if https_result and https_result["status"] is not None:
        print(f"HTTPS        : {https_result['status']} {https_result['reason']}")
    else:
        print("HTTPS        : NOT AVAILABLE")

    if tls_result and tls_result.get("version"):
        print(f"TLS Version  : {tls_result['version']}")
        print(f"Certificate  : {tls_result['certificate']}")
        print(f"Issuer       : {tls_result['issuer']}")
        print(f"TLS Status   : {tls_result['status']}")
        if tls_result["days_remaining"] is not None:
            print(f"Days Remaining: {tls_result['days_remaining']}")

    print(f"Overall Risk : {risk['overall']}")
    print("================================")
    print()
    print(timer.render())
    print("================================")


# ==========================================
# MAIN
# ==========================================

def run(raw_target: str):
    timer = StageTimer()

    try:
        target = parse_target(raw_target)
    except InvalidTargetError as exc:
        print(f"[TRACE] Invalid target: {exc}")
        return

    print()
    print(f"Target: {target.display}")
    print("TRACE is starting...")

    # ---------------- DNS ----------------
    with timer.measure("DNS"):
        ip = check_dns(target.host)

    section("DNS")
    if ip:
        print(f"[DNS] Resolved: {ip}")
    print(f"[ANALYSIS] {analyze_dns(ip)}")

    if not ip:
        print()
        print("[TRACE] Unable to continue.")
        print()
        print(timer.render())
        return

    # ---------------- TCP ----------------
    ports_to_check = [target.port] if target.port else DEFAULT_PORTS

    with timer.measure("TCP"):
        tcp_result = check_ports(ip, ports=ports_to_check)

    open_ports = tcp_result["open_ports"]

    section("TCP")
    for port, status in tcp_result["results"].items():
        print(f"[TCP] Port {port}: {status}")
    for line in analyze_tcp(open_ports):
        print(f"[ANALYSIS] {line}")

    # ---------------- HTTP ----------------
    http_result = None
    if 80 in open_ports:
        section("HTTP")
        with timer.measure("HTTP"):
            http_result = make_request(target.host, 80, target.path)

        if http_result["version"]:
            print(f"[HTTP] Version: {http_result['version']}")
        print(f"[HTTP] Status: {http_result['status']}")
        print(f"[HTTP] Message: {http_result['reason']}")
        if http_result["location"]:
            print(f"[HTTP] Redirect: {http_result['location']}")
        print(f"[ANALYSIS] {analyze_http(http_result['status'])}")

        if http_result["status"] in REDIRECT_STATUSES:
            with timer.measure("Redirects"):
                chain = follow_chain(f"http://{target.host}{target.path}")
            print()
            print_redirect_chain(chain)
            upgrade = check_https_upgrade(chain)
            print()
            print("[TRANSPORT] Checking HTTP → HTTPS behavior...")
            if upgrade["observed"]:
                print("[TRANSPORT] HTTPS Upgrade: OBSERVED")
            else:
                print("[TRANSPORT] HTTPS Upgrade: NOT OBSERVED")
            print(f"[TRANSPORT] Evidence: {upgrade['evidence']}")

    # ---------------- HTTPS ----------------
    https_result = None
    if 443 in open_ports:
        section("HTTPS")
        with timer.measure("HTTPS"):
            https_result = make_request(target.host, 443, target.path)

        if https_result["version"]:
            print(f"[HTTPS] Version: {https_result['version']}")
        print(f"[HTTPS] Status: {https_result['status']}")
        print(f"[HTTPS] Message: {https_result['reason']}")
        if https_result["location"]:
            print(f"[HTTPS] Redirect: {https_result['location']}")
        print(f"[ANALYSIS] {analyze_http(https_result['status'])}")

    # ---------------- TLS ----------------
    tls_result = None
    if 443 in open_ports:
        section("TLS")
        with timer.measure("TLS"):
            tls_result = inspect_tls(target.host)

        if tls_result.get("version"):
            print(f"[TLS] Version: {tls_result['version']}")
            print(f"[TLS] Cipher: {tls_result['cipher']}")
            print(f"[TLS] Certificate: {tls_result['certificate']}")
            print(f"[TLS] Issuer: {tls_result['issuer']}")
            print(f"[TLS] Valid Until: {tls_result['valid_until']}")
            if tls_result["days_remaining"] is not None:
                print(f"[TLS] Days Remaining: {tls_result['days_remaining']}")
            print(f"[TLS] Certificate Status: {tls_result['status']}")
        else:
            print("[TLS] Unable to inspect certificate.")

    # ---------------- Security Findings ----------------
    findings = []
    if https_result and https_result["headers"]:
        findings = analyze_security_headers(https_result["headers"])
        print_findings(findings)

    risk = calculate_risk(findings)

    print()
    print(f"[SECURITY] Findings: {len(findings)}")
    print(f"[SECURITY] High: {risk['high']}  Medium: {risk['medium']}  "
          f"Low: {risk['low']}  Info: {risk['info']}")
    print(f"[SECURITY] Overall Risk: {risk['overall']}")
    print("[SECURITY] Scope: Passive network and HTTP checks")

    print_security_summary(findings, risk, tls_result)
    print_final_report(
        target.display, ip, open_ports, http_result, https_result, tls_result, risk, timer
    )


def main():
    banner()
    raw_target = input("Enter target: ")
    run(raw_target)


if __name__ == "__main__":
    main()
