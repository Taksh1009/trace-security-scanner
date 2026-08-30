"""
TRACE — HTTP/HTTPS Checker
============================
Performs a single GET request against a host/port and reports back
status, version, headers, and any redirect target. Passive: one
request, no crawling, no payloads beyond a standard GET.
"""

import http.client
import ssl

DEFAULT_TIMEOUT = 5
USER_AGENT = "TRACE/3.0"


def _version_string(http_version_code):
    if http_version_code == 10:
        return "HTTP/1.0"
    if http_version_code == 11:
        return "HTTP/1.1"
    return f"HTTP/{http_version_code}"


def make_request(host: str, port: int, path: str = "/", timeout: float = DEFAULT_TIMEOUT):
    """
    Perform a single GET request.

    Returns a dict:
        {
            "status": int | None,
            "reason": str,
            "version": str | None,
            "headers": dict (lowercased keys),
            "location": str | None,
        }
    On failure, status/version/location are None and "reason" holds
    the error message.
    """
    try:
        if port == 443:
            context = ssl.create_default_context()
            connection = http.client.HTTPSConnection(
                host, port, timeout=timeout, context=context
            )
        else:
            connection = http.client.HTTPConnection(host, port, timeout=timeout)

        connection.request("GET", path, headers={"User-Agent": USER_AGENT})
        response = connection.getresponse()

        headers = {key.lower(): value for key, value in response.getheaders()}
        status = response.status
        reason = response.reason
        version = _version_string(response.version)
        location = headers.get("location")

        connection.close()

        return {
            "status": status,
            "reason": reason,
            "version": version,
            "headers": headers,
            "location": location,
        }

    except Exception as exc:  # noqa: BLE001 - deliberately broad for a passive probe
        return {
            "status": None,
            "reason": str(exc),
            "version": None,
            "headers": {},
            "location": None,
        }


def analyze_http(status_code):
    """Human-readable one-line summary for an HTTP status code."""
    if status_code is None:
        return "HTTP request failed."

    if 200 <= status_code < 300:
        return "HTTP request successful."

    if 300 <= status_code < 400:
        return "Server returned a redirect."

    if 400 <= status_code < 500:
        return "Client-side HTTP error."

    if 500 <= status_code < 600:
        return "Server-side HTTP error."

    return "Unknown HTTP status."
