import pytest
from unittest.mock import MagicMock, PropertyMock

from NetBoxHandler import get_host_by_ip, NetBoxHandler


# NB Model classes
class Name:
    name = "test"
    id = 1


class Device:
    device = Name()
    id = 1


class Ip:
    def __init__(self, address):
        self.address=address
        self.assigned_object = Device()
        self.id = 1


class VirtualMachine:
    virtual_machine = Name()


class IpVirtual:
    assigned_object = VirtualMachine()


class WrongObject:
    assigned_object = "test"


class Tag():
    def __init__(self, id, name):
        self.id = id
        self.name = name


scan_host_service = {'127.0.0.1':
                         {'macaddress': None, 'subnet': 'test', 'dns_name': 'localhost',
                          'services':
                              {'22':
                                   {'protocol': 'tcp', 'portid': '22', 'state': 'open',
                                    'service': {'name': 'ssh', 'product': 'OpenSSH',
                                                'version': '7.4p1 Debian 10+deb9u7',
                                                'extrainfo': 'protocol 2.0', 'ostype': 'Linux',
                                                'method': 'probed', 'conf': '10'}, 'scripts': []},
                               '80': {'protocol': 'tcp', 'portid': '80', 'state': 'open',
                                      'service': {'name': 'http', 'product': 'lighttpd'}},
                               '443': {'protocol': 'tcp', 'portid': '443', 'state': 'open',
                                       'service': {'name': 'http', 'product': 'lighttpd', 'tunnel': 'ssl'}}}}}


def test_correct_instance_device_get_host_by_ip():
    nb_device_ip = Ip("127.0.0.1")
    test, device_type = get_host_by_ip(nb_device_ip)
    assert (isinstance(test, Name))
    assert device_type == "device"


def test_correct_instance_virtual_get_host_by_ip():
    nb_virtual_ip = IpVirtual()
    test, device_type = get_host_by_ip(nb_virtual_ip)
    assert (isinstance(test, Name))
    assert device_type == "virtual_machine"


def test_invalid_get_host_by_ip():
    with pytest.raises(SystemExit) as pytest_wrapped_e:
        get_host_by_ip("wrong")
        assert pytest_wrapped_e.value.code == 1


def test_invalid_object_get_host_by_ip():
    test, device_type = get_host_by_ip(WrongObject())
    assert not test
    assert not device_type


# TODO: PENDING TO IMPLEMENT
# @pytest.fixture()
# def mock_pynetbox_session(monkeypatch):
#     mock_pynetbox_session = MagicMock()
#     monkeypatch.setattr('requests.Response', mock_pynetbox_session)
#     return mock_pynetbox_session


@pytest.fixture()
def mock_pynetbox_con(monkeypatch):
    mock_pynetbox_con = MagicMock()
    monkeypatch.setattr('pynetbox.api', mock_pynetbox_con)
    mock_pynetbox_con.return_value.extras.tags.get.return_value = Tag(1, "test")
    type(mock_pynetbox_con.return_value).version = PropertyMock(return_value="2.9")
    return mock_pynetbox_con


def test_nb_host_unreachable():
    with pytest.raises(SystemExit):
        NetBoxHandler("http://test:8000", "1234", False, "test", False)


def test_nb_wrong_schema():
    with pytest.raises(SystemExit):
        NetBoxHandler("test", "1234", False, "test", False)


# TODO: PENDING TO IMPLEMENT
# def test_nb_invalid_token(mock_pynetbox_session):
#     with pytest.raises(SystemExit) as pytest_wrapped_e:
#         NetBoxHandler("http://test:8000", "1234",
#                                  False, "test", False)
#         assert pytest_wrapped_e.value.code == 1


def test_nb_wrong_version(mock_pynetbox_con):
    type(mock_pynetbox_con.return_value).version = PropertyMock(return_value="2.8")
    with pytest.raises(Exception):
        NetBoxHandler("http://test:8000", "1234", False, "test", False)


@pytest.fixture()
def nb(mock_pynetbox_con):
    nb = NetBoxHandler("http://test:8000", "1234", False, "test", False)
    return nb


def test_NetboxHandler_run(nb):
    nb.all_ips = []
    nb.run({"127.0.0.1": {}})
    nb.run({'192.168.4.1': {'macaddress': "00:11:22:33:44:55", 'subnet': '192.168.4.0/24'}})
    nb.run({'192.168.4.2': {'macaddress': None, 'subnet': '192.168.4.0/24', 'dns_name': 'test.test.local'}})


def test_NetboxHandler_creation_scripttag(mock_pynetbox_con):
    mock_pynetbox_con.return_value.extras.tags.get.return_value = None
    mock_pynetbox_con.return_value.extras.tags.create.return_value = True
    NetBoxHandler("http://test:8000", "1234", False, "test_tag", False)
    mock_pynetbox_con.return_value.extras.tags.get.assert_called_with(name="test_tag")


def test_NetboxHandler_create_service(mock_pynetbox_con):
    nb = NetBoxHandler("http://test:8000", "1234", False, "test_tag", False)
    ip = Ip("127.0.0.1/32")
    nb.all_ips = [ip]
    nb.run(scan_host_service)
    assert mock_pynetbox_con.return_value.ipam.services.create.call_count == 3
