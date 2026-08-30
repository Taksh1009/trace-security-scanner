import pytest

from modules.input_parser import parse_target, InvalidTargetError


def test_bare_hostname():
    t = parse_target("google.com")
    assert t.host == "google.com"
    assert t.port is None
    assert t.scheme is None


def test_https_scheme():
    t = parse_target("https://example.com")
    assert t.host == "example.com"
    assert t.scheme == "https"


def test_http_scheme():
    t = parse_target("http://example.com")
    assert t.host == "example.com"
    assert t.scheme == "http"


def test_trailing_slash():
    t = parse_target("example.com/")
    assert t.host == "example.com"
    assert t.path == "/"


def test_explicit_port_no_scheme():
    # This is the case that was broken in the prototype.
    t = parse_target("google.com:443")
    assert t.host == "google.com"
    assert t.port == 443


def test_explicit_port_with_path_and_query():
    t = parse_target("google.com:8080/path?x=1")
    assert t.host == "google.com"
    assert t.port == 8080
    assert t.path == "/path?x=1"


def test_scheme_and_port():
    t = parse_target("https://example.com:443/a/b")
    assert t.host == "example.com"
    assert t.port == 443
    assert t.path == "/a/b"


def test_empty_string_raises():
    with pytest.raises(InvalidTargetError):
        parse_target("")


def test_whitespace_only_raises():
    with pytest.raises(InvalidTargetError):
        parse_target("   ")


def test_none_raises():
    with pytest.raises(InvalidTargetError):
        parse_target(None)


def test_invalid_port_raises():
    with pytest.raises(InvalidTargetError):
        parse_target("google.com:notaport")


def test_display_without_port():
    t = parse_target("google.com")
    assert t.display == "google.com"


def test_display_with_port():
    t = parse_target("google.com:8443")
    assert t.display == "google.com:8443"
