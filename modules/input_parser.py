"""
TRACE — Input Parser
======================
Normalizes whatever the user types into a clean, reliable target:
host, optional explicit port, optional scheme.

Handles:
    google.com
    https://google.com
    http://google.com
    google.com/
    google.com:443
    google.com:8080/path?x=1
    https://google.com:443/a/b

Rejects empty / unparseable input with a clear ValueError rather than
letting it silently fail downstream in DNS resolution.
"""

from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse


class InvalidTargetError(ValueError):
    """Raised when a target string cannot be parsed into a usable host."""


@dataclass
class ParsedTarget:
    host: str
    scheme: Optional[str] = None
    port: Optional[int] = None
    path: str = "/"

    @property
    def display(self) -> str:
        """A clean human-readable form for banners/reports."""
        if self.port:
            return f"{self.host}:{self.port}"
        return self.host


def parse_target(raw: str) -> ParsedTarget:
    """
    Parse raw user input into a ParsedTarget.

    Raises InvalidTargetError if no usable hostname can be extracted.
    """
    if raw is None:
        raise InvalidTargetError("No target provided.")

    cleaned = raw.strip()

    if not cleaned:
        raise InvalidTargetError("No target provided.")

    # If there's no scheme, urlparse won't treat the string as a netloc
    # unless it starts with '//'. This is the fix for inputs like
    # "google.com:443" being misread as a relative path.
    if "://" in cleaned:
        candidate = cleaned
    else:
        candidate = "//" + cleaned

    parsed = urlparse(candidate)

    hostname = parsed.hostname

    if not hostname:
        raise InvalidTargetError(
            f"Could not extract a valid hostname from '{raw}'."
        )

    scheme = parsed.scheme or None

    try:
        port = parsed.port
    except ValueError:
        # e.g. a non-numeric port like "google.com:abc"
        raise InvalidTargetError(
            f"'{raw}' contains an invalid port."
        )

    path = parsed.path or "/"

    if parsed.query:
        path = f"{path}?{parsed.query}"

    return ParsedTarget(host=hostname, scheme=scheme, port=port, path=path)
