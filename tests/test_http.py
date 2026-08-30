from unittest.mock import MagicMock, patch

from modules.http_checker import make_request, analyze_http


def _fake_response(status=200, reason="OK", version=11, headers=None):
    resp = MagicMock()
    resp.status = status
    resp.reason = reason
    resp.version = version
    resp.getheaders.return_value = list((headers or {}).items())
    return resp


def test_http_200():
    fake_conn = MagicMock()
    fake_conn.getresponse.return_value = _fake_response(200, "OK", 11, {"Content-Type": "text/html"})

    with patch("http.client.HTTPConnection", return_value=fake_conn):
        result = make_request("example.com", 80)

    assert result["status"] == 200
    assert result["version"] == "HTTP/1.1"
    assert result["headers"]["content-type"] == "text/html"
    assert result["location"] is None


def test_http_301_redirect():
    fake_conn = MagicMock()
    fake_conn.getresponse.return_value = _fake_response(
        301, "Moved Permanently", 11, {"Location": "https://example.com/"}
    )

    with patch("http.client.HTTPConnection", return_value=fake_conn):
        result = make_request("example.com", 80)

    assert result["status"] == 301
    assert result["location"] == "https://example.com/"


def test_https_uses_ssl_context():
    fake_conn = MagicMock()
    fake_conn.getresponse.return_value = _fake_response(200, "OK", 11, {})

    with patch("http.client.HTTPSConnection", return_value=fake_conn) as mock_https:
        result = make_request("example.com", 443)

    mock_https.assert_called_once()
    assert result["status"] == 200


def test_http_connection_error():
    with patch("http.client.HTTPConnection", side_effect=OSError("connection refused")):
        result = make_request("nonexistent.invalid", 80)

    assert result["status"] is None
    assert "connection refused" in result["reason"]


def test_analyze_http_success():
    assert analyze_http(200) == "HTTP request successful."


def test_analyze_http_redirect():
    assert analyze_http(301) == "Server returned a redirect."


def test_analyze_http_client_error():
    assert analyze_http(404) == "Client-side HTTP error."


def test_analyze_http_server_error():
    assert analyze_http(500) == "Server-side HTTP error."


def test_analyze_http_none():
    assert analyze_http(None) == "HTTP request failed."


def test_analyze_http_unknown():
    assert analyze_http(999) == "Unknown HTTP status."
