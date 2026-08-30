import socket
from unittest.mock import MagicMock, patch

from modules.tcp_checker import check_ports, analyze_tcp


def _make_fake_socket(connect_ex_return=0, raises=None):
    fake_sock = MagicMock()
    if raises:
        fake_sock.connect_ex.side_effect = raises
    else:
        fake_sock.connect_ex.return_value = connect_ex_return
    return fake_sock


def test_port_open():
    with patch("socket.socket", return_value=_make_fake_socket(connect_ex_return=0)):
        result = check_ports("1.2.3.4", ports=[80])
    assert result["open_ports"] == [80]
    assert result["results"][80] == "OPEN"


def test_port_closed():
    with patch("socket.socket", return_value=_make_fake_socket(connect_ex_return=1)):
        result = check_ports("1.2.3.4", ports=[443])
    assert result["open_ports"] == []
    assert result["results"][443] == "CLOSED"


def test_port_error():
    with patch("socket.socket", return_value=_make_fake_socket(raises=socket.error("boom"))):
        result = check_ports("1.2.3.4", ports=[80])
    assert result["results"][80] == "ERROR"
    assert result["open_ports"] == []


def test_analyze_tcp_both_open():
    lines = analyze_tcp([80, 443])
    assert "port 80" in lines[0]
    assert "available" in lines[0]
    assert "port 443" in lines[1]
    assert "available" in lines[1]


def test_analyze_tcp_none_open():
    lines = analyze_tcp([])
    assert "not detected" in lines[0]
    assert "not detected" in lines[1]
