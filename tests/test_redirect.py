from unittest.mock import patch

from modules.redirect_checker import follow_chain, check_https_upgrade, get_status_message


def test_follow_chain_single_hop_no_redirect():
    fake_result = {"status": 200, "reason": "OK", "version": "HTTP/1.1",
                   "headers": {}, "location": None}

    with patch("modules.redirect_checker.make_request", return_value=fake_result):
        chain = follow_chain("http://example.com/")

    assert len(chain) == 1
    assert chain[0]["status"] == 200
    assert chain[0]["location"] is None


def test_follow_chain_redirect_then_final():
    responses = [
        {"status": 301, "reason": "Moved Permanently", "version": "HTTP/1.1",
         "headers": {}, "location": "https://example.com/"},
        {"status": 200, "reason": "OK", "version": "HTTP/1.1",
         "headers": {}, "location": None},
    ]

    with patch("modules.redirect_checker.make_request", side_effect=responses):
        chain = follow_chain("http://example.com/")

    assert len(chain) == 2
    assert chain[0]["status"] == 301
    assert chain[0]["location"] == "https://example.com/"
    assert chain[1]["status"] == 200


def test_follow_chain_stops_on_request_failure():
    fake_result = {"status": None, "reason": "boom", "version": None,
                   "headers": {}, "location": None}

    with patch("modules.redirect_checker.make_request", return_value=fake_result):
        chain = follow_chain("http://example.com/")

    assert chain == []


def test_https_upgrade_observed():
    chain = [{"status": 301, "location": "https://example.com/", "url": "http://example.com/", "scheme": "http"}]
    result = check_https_upgrade(chain)
    assert result["observed"] is True
    assert result["evidence"] == "https://example.com/"


def test_https_upgrade_not_observed():
    chain = [{"status": 200, "location": None, "url": "http://example.com/", "scheme": "http"}]
    result = check_https_upgrade(chain)
    assert result["observed"] is False
    assert "No HTTPS destination" in result["evidence"]


def test_get_status_message_known():
    assert get_status_message(404) == "Not Found"


def test_get_status_message_unknown():
    assert get_status_message(999) == "Unknown"
