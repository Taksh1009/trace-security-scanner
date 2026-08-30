import socket
from unittest.mock import patch

from modules.dns_checker import check_dns, analyze_dns


def test_dns_success():
    with patch("socket.gethostbyname", return_value="93.184.216.34"):
        ip = check_dns("example.com")
    assert ip == "93.184.216.34"


def test_dns_failure():
    with patch("socket.gethostbyname", side_effect=socket.gaierror):
        ip = check_dns("this-domain-does-not-exist.invalid")
    assert ip is None


def test_analyze_dns_success_message():
    assert analyze_dns("1.2.3.4") == "DNS resolution successful."


def test_analyze_dns_failure_message():
    assert analyze_dns(None) == "DNS resolution failed."
