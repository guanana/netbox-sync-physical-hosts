import pytest
from unittest.mock import MagicMock, PropertyMock

from NetBoxHandler import get_host_by_ip, NetBoxHandler


# NB Model classes
class Name:
    name = "test"


class Device:
    device = Name()


class Ip:
    assigned_object = Device()


class VirtualMachine:
    virtual_machine = Name()


class IpVirtual:
    assigned_object = VirtualMachine()


def test_get_host_by_ip():
    nb_device_ip = Ip()
    test, device_type = get_host_by_ip(nb_device_ip)
    assert(isinstance(test, Name))
    assert device_type == "device"
    nb_virtual_ip = IpVirtual()
    test, device_type = get_host_by_ip(nb_virtual_ip)
    assert(isinstance(test, Name))
    assert device_type == "virtual_machine"

@pytest.fixture()
def mock_pynetbox_con(monkeypatch):
    mock_pynetbox_con = MagicMock()
    monkeypatch.setattr('pynetbox.api', mock_pynetbox_con)
    type(mock_pynetbox_con.return_value).version = PropertyMock(return_value="2.9")
    return mock_pynetbox_con

@pytest.fixture()
def nb(mock_pynetbox_con):
    nb = NetBoxHandler("http://localhost:8000", "1234",
                                 False, "test", False)
    return nb

def test_NetboxHandlerrun(nb):
    nb.all_ips = []
    nb.run({"127.0.0.1": {}})
    nb.run({'192.168.4.1': {'macaddress': "00:11:22:33:44:55", 'subnet': '192.168.4.0/24'}})
    nb.run({'192.168.4.2': {'macaddress': None, 'subnet': '192.168.4.0/24', 'dns_name': 'test.test.local'}})

