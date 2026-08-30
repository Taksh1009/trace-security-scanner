"""
TRACE — TLS Checker
=====================
Inspects the TLS certificate presented by a host on port 443:
version, cipher, subject, issuer, validity window, and days
remaining until expiry. Passive: standard TLS handshake only.
"""

import socket
import ssl
from datetime import datetime, timezone

DEFAULT_TIMEOUT = 5
EXPIRING_SOON_THRESHOLD_DAYS = 30


def _extract_field(rdn_sequence, wanted_keys):
    """Pull the first matching key from an X.509 subject/issuer tuple."""
    for field in rdn_sequence:
        for key, value in field:
            if key in wanted_keys:
                return value
    return None


def inspect(host: str, port: int = 443, timeout: float = DEFAULT_TIMEOUT):
    """
    Connect to `host`:`port` and inspect its TLS certificate.

    Returns a dict with version, cipher, certificate, issuer,
    valid_from, valid_until, days_remaining, and status
    (HEALTHY / EXPIRING SOON / EXPIRED / UNKNOWN / ERROR).
    """
    try:
        context = ssl.create_default_context()

        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as secure_sock:
                tls_version = secure_sock.version()
                cipher_info = secure_sock.cipher()
                certificate = secure_sock.getpeercert()

        cipher = cipher_info[0] if cipher_info else "Unknown"

        subject = certificate.get("subject", [])
        issuer = certificate.get("issuer", [])

        certificate_name = _extract_field(subject, {"commonName"}) or "Unknown"
        issuer_name = (
            _extract_field(issuer, {"organizationName"})
            or _extract_field(issuer, {"commonName"})
            or "Unknown"
        )

        not_before = certificate.get("notBefore", "Unknown")
        not_after = certificate.get("notAfter", "Unknown")

        days_remaining = None
        if not_after != "Unknown":
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            now = datetime.now(timezone.utc).replace(tzinfo=None)
            days_remaining = (expiry - now).days

        if days_remaining is None:
            status = "UNKNOWN"
        elif days_remaining < 0:
            status = "EXPIRED"
        elif days_remaining < EXPIRING_SOON_THRESHOLD_DAYS:
            status = "EXPIRING SOON"
        else:
            status = "HEALTHY"

        return {
            "version": tls_version,
            "cipher": cipher,
            "certificate": certificate_name,
            "issuer": issuer_name,
            "valid_from": not_before,
            "valid_until": not_after,
            "days_remaining": days_remaining,
            "status": status,
        }

    except Exception:  # noqa: BLE001 - passive probe, any TLS failure is just "ERROR"
        return {
            "version": None,
            "cipher": None,
            "certificate": None,
            "issuer": None,
            "valid_from": None,
            "valid_until": None,
            "days_remaining": None,
            "status": "ERROR",
        }
