"""
TRACE — TCP Port Checker
==========================
Checks whether specific TCP ports are open on a target IP.
Passive: a plain connect() attempt, no banner grabbing or payloads.
"""

import socket

DEFAULT_PORTS = [80, 443]
DEFAULT_TIMEOUT = 5


def check_ports(ip: str, ports=None, timeout: float = DEFAULT_TIMEOUT):
    """
    Attempt a TCP connection to each port in `ports`.

    Returns:
        dict: {
            "open_ports": [int, ...],
            "results": {port: "OPEN" | "CLOSED" | "ERROR", ...}
        }
    """
    if ports is None:
        ports = DEFAULT_PORTS

    open_ports = []
    results = {}

    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        try:
            result = sock.connect_ex((ip, port))

            if result == 0:
                results[port] = "OPEN"
                open_ports.append(port)
            else:
                results[port] = "CLOSED"

        except socket.error:
            results[port] = "ERROR"

        finally:
            sock.close()

    return {"open_ports": open_ports, "results": results}


def analyze_tcp(open_ports):
    """Human-readable summary lines for TCP results."""
    messages = []

    if 80 in open_ports:
        messages.append("HTTP service appears available on port 80.")
    else:
        messages.append("HTTP service was not detected on port 80.")

    if 443 in open_ports:
        messages.append("HTTPS service appears available on port 443.")
    else:
        messages.append("HTTPS service was not detected on port 443.")

    return messages
