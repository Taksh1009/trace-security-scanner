"""
TRACE — DNS Checker
=====================
Resolves a hostname to an IPv4 address using only the standard library.
Passive: performs a single forward lookup, nothing more.
"""

import socket


def check_dns(hostname: str):
    """
    Resolve `hostname` to an IP address.

    Returns:
        str: the resolved IP address on success.
        None: if resolution fails.
    """
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def analyze_dns(ip):
    """Human-readable one-line summary of a DNS result."""
    if ip:
        return "DNS resolution successful."
    return "DNS resolution failed."
