from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

from modules.tls_checker import inspect


def _fmt(dt):
    return dt.strftime("%b %d %H:%M:%S %Y GMT")


def _build_mocks(not_after_dt, version="TLSv1.3", cipher_name="TLS_AES_256_GCM_SHA384"):
    certificate = {
        "subject": [(("commonName", "example.com"),)],
        "issuer": [(("organizationName", "Example Trust Services"),)],
        "notBefore": _fmt(datetime.now(timezone.utc) - timedelta(days=30)),
        "notAfter": _fmt(not_after_dt),
    }

    secure_sock = MagicMock()
    secure_sock.version.return_value = version
    secure_sock.cipher.return_value = (cipher_name, "TLSv1.3", 256)
    secure_sock.getpeercert.return_value = certificate
    secure_sock.__enter__.return_value = secure_sock
    secure_sock.__exit__.return_value = False

    raw_sock = MagicMock()
    raw_sock.__enter__.return_value = raw_sock
    raw_sock.__exit__.return_value = False

    context = MagicMock()
    context.wrap_socket.return_value = secure_sock

    return raw_sock, context


def test_tls_healthy_certificate():
    not_after = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(days=90)
    raw_sock, context = _build_mocks(not_after)

    with patch("socket.create_connection", return_value=raw_sock), \
         patch("ssl.create_default_context", return_value=context):
        result = inspect("example.com")

    assert result["status"] == "HEALTHY"
    assert result["certificate"] == "example.com"
    assert result["issuer"] == "Example Trust Services"
    assert result["days_remaining"] > 60


def test_tls_expiring_soon():
    not_after = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(days=10)
    raw_sock, context = _build_mocks(not_after)

    with patch("socket.create_connection", return_value=raw_sock), \
         patch("ssl.create_default_context", return_value=context):
        result = inspect("example.com")

    assert result["status"] == "EXPIRING SOON"


def test_tls_expired_certificate():
    not_after = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=5)
    raw_sock, context = _build_mocks(not_after)

    with patch("socket.create_connection", return_value=raw_sock), \
         patch("ssl.create_default_context", return_value=context):
        result = inspect("example.com")

    assert result["status"] == "EXPIRED"
    assert result["days_remaining"] < 0


def test_tls_connection_error():
    with patch("socket.create_connection", side_effect=OSError("connection refused")):
        result = inspect("nonexistent.invalid")

    assert result["status"] == "ERROR"
    assert result["version"] is None
