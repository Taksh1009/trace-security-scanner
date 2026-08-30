"""
TRACE — Redirect Chain Checker
================================
Follows HTTP redirects from a starting URL and records each hop.
Also evaluates whether an HTTPS destination was ever observed in
the chain, using conservative, evidence-based wording (never claims
a site is "insecure" — only reports what was or wasn't observed).
"""

from urllib.parse import urlparse

from modules.http_checker import make_request

DEFAULT_MAX_REDIRECTS = 5
REDIRECT_STATUSES = {301, 302, 303, 307, 308}

STATUS_MESSAGES = {
    200: "OK", 201: "Created", 204: "No Content",
    301: "Moved Permanently", 302: "Found", 303: "See Other",
    307: "Temporary Redirect", 308: "Permanent Redirect",
    400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found",
    500: "Internal Server Error", 502: "Bad Gateway", 503: "Service Unavailable",
}


def get_status_message(status):
    return STATUS_MESSAGES.get(status, "Unknown")


def follow_chain(start_url: str, max_redirects: int = DEFAULT_MAX_REDIRECTS):
    """
    Follow redirects starting at `start_url`.

    Returns a list of hop dicts:
        {"status": int, "location": str | None, "url": str, "scheme": str}
    """
    chain = []
    current_url = start_url

    for _ in range(max_redirects):
        parsed = urlparse(current_url)
        hostname = parsed.hostname
        scheme = parsed.scheme or "http"

        if not hostname:
            break

        port = 443 if scheme == "https" else 80
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        result = make_request(hostname, port, path)

        if result["status"] is None:
            break

        location = result["location"]

        chain.append({
            "status": result["status"],
            "location": location,
            "url": current_url,
            "scheme": scheme,
        })

        if not location:
            break

        if location.startswith("/"):
            current_url = f"{scheme}://{hostname}{location}"
        else:
            current_url = location

    return chain


def check_https_upgrade(chain):
    """
    Evaluate whether the redirect chain shows evidence of an HTTPS
    destination. Deliberately conservative wording: reports what was
    or wasn't observed rather than making a security claim.

    Returns:
        dict: {"observed": bool, "evidence": str | None}
    """
    for hop in chain:
        location = hop.get("location")
        if location and location.lower().startswith("https://"):
            return {"observed": True, "evidence": location}

    return {
        "observed": False,
        "evidence": "No HTTPS destination found in redirect chain",
    }
