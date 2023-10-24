from unittest.mock import MagicMock
import pytest

from netbox_sync_physical_hosts.config.config import parse_config

def test_get_conf_call(monkeypatch):
    testargs = ["prog", "-u", "http://test", "-p", "1234", "-n", "127.0.0.1"]
    monkeypatch.setattr('sys.argv', testargs)
    testconf = parse_config()
    assert testconf.nb_url == "http://test"
    assert testconf.nb_token == "1234"
    assert testconf.networks == "127.0.0.1"

def test_failed_conf_call(monkeypatch):
    with pytest.raises(SystemExit) as pytest_wrapped_e:
        testargs = ["prog", "-c", "test"]
        monkeypatch.setattr('sys.argv', testargs)
        parse_config()
        assert pytest_wrapped_e.value.code == 2

