import logging

import pytest
from unittest.mock import MagicMock, PropertyMock
from netbox_sync_physical_hosts.netboxhandler.NetBoxHandler import get_host_by_ip, NetBoxHandler
# NB Model classes

class Device:
    name = "test"
    id = 1


class Dcim:
    device = Device()


class Ip:
    def __init__(self, address, assign_host=True, virtual=False):
        self.address = address
        if assign_host:
            if virtual:
                self.assigned_object = VirtualMachine()
            else:
                self.assigned_object = Dcim()
        else:
            self.assigned_object = None
        self.id = 1

    def __getitem__(self, item):
         if item == "id":
            return 1


class VirtualMachine:
    virtual_machine = Device()


class WrongObject:
    assigned_object = "test"


class Tag:
    def __init__(self, id,  name):
        self.id = id
        self.name = name


class Service:
    def __init__(self, device, portid, ip, tag):
        self.virtual_machine = device
        self.device = device
        self.port = int(portid)
        self.ipaddresses = ip
        self.tags = tag

    def update(self, test):
        return

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


def test_invalid_get_host_by_ip():
    with pytest.raises(SystemExit) as pytest_wrapped_e:
        get_host_by_ip("wrong")
        assert pytest_wrapped_e.value.code == 1


def test_invalid_object_get_host_by_ip():
    test, device_type = get_host_by_ip(WrongObject())
    assert not test
    assert not device_type


@pytest.fixture()
def mock_pynetbox_con(monkeypatch):
    mock_pynetbox_con = MagicMock()
    monkeypatch.setattr('pynetbox.api', mock_pynetbox_con)
    mock_pynetbox_con.return_value.extras.tags.get.return_value = Tag(1, "test")
    type(mock_pynetbox_con.return_value).version = PropertyMock(return_value="2.9")
    return mock_pynetbox_con


def test_nb_host_unreachable():
    with pytest.raises(SystemExit):
        NetBoxHandler("http://unresolvable:8000", "1234", False, "test", False)


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


def test_netboxhandler_run_ip_no_host(caplog, nb):
    ip = Ip("127.0.0.1/32", assign_host=False)
    nb.all_ips = [ip]
    with caplog.at_level(logging.DEBUG):
        nb.run({"127.0.0.1": {}})
        assert [True for record in caplog.records if record.message == 'Not host found for 127.0.0.1']



def test_create_ip(nb):
    nb.all_ips = []
    nb.run({'192.168.4.1': {'macaddress': "00:11:22:33:44:55", 'subnet': '192.168.4.0/24'}})
    nb.run({'192.168.4.2': {'macaddress': None, 'subnet': '192.168.4.0/24', 'dns_name': 'test.test.local'}})


def test_create_ip_with_no_mask(caplog, nb):
    nb.all_ips = []
    with caplog.at_level(logging.DEBUG):
        nb.run({'192.168.4.1': {'macaddress': "00:11:22:33:44:55", 'subnet': '192.168.4.0'}})
        assert [True for record in caplog.records if record.message == 'Problem with IP 192.168.4.1']


def test_netboxhandler_creation_scripttag(mock_pynetbox_con):
    mock_pynetbox_con.return_value.extras.tags.get.return_value = None
    mock_pynetbox_con.return_value.extras.tags.create.return_value = True
    NetBoxHandler("http://test:8000", "1234", False, "test_tag", False)
    mock_pynetbox_con.return_value.extras.tags.get.assert_called_with(name="test_tag")


@pytest.fixture()
def aux_create_service(mock_pynetbox_con):
    nb = NetBoxHandler("http://test:8000", "1234", False, "test_tag", False)
    mock_pynetbox_con.return_value.ipam.services.update.return_value = True
    return nb


def aux_add_ips_and_services(nb, ips:list, services:list):
    nb.all_ips = ips
    nb.all_services = services


def test_netboxhandler_create_service(aux_create_service, mock_pynetbox_con):
    nb = aux_create_service
    ip = Ip("127.0.0.1/32")
    device = ip.assigned_object.device
    nb_service = Service(device, 22, [ip], [Tag(1, "test_tag")])
    aux_add_ips_and_services(nb, [ip],[nb_service])
    nb.run(scan_host_service)
    assert mock_pynetbox_con.return_value.ipam.services.create.call_count == 2
    assert mock_pynetbox_con.return_value.ipam.services.update.call_count == 0


def test_netboxhandler_create_service_virtual_machine(aux_create_service, mock_pynetbox_con):
    nb = aux_create_service
    virtual_ip = Ip("127.0.0.1/32", virtual=True)
    device = virtual_ip.assigned_object.virtual_machine
    nb_service = Service(device, 22, [virtual_ip], [Tag(1, "test_tag")])
    aux_add_ips_and_services(nb, [virtual_ip],[nb_service])
    nb.run(scan_host_service)
    print(nb)
    assert mock_pynetbox_con.return_value.ipam.services.create.call_count == 2
    assert mock_pynetbox_con.return_value.ipam.services.update.call_count == 0


def test_netboxhandler_try_update_service_no_tag(caplog, mock_pynetbox_con):
    nb = NetBoxHandler("http://test:8000", "1234", False, "test_tag", False)
    ip = Ip("127.0.0.1/32")
    device = ip.assigned_object.device
    service_tag = Tag(2, "no_matching_tag_id")
    nb_service22 = Service(device, 22, [ip], [service_tag])
    nb_service80 = Service(device, 80, [ip], [])
    nb_service443 = Service(device, 443, [ip], [service_tag])
    nb.all_ips = [ip]
    nb.all_services = [nb_service22, nb_service80, nb_service443]
    nb.run(scan_host_service)
    assert mock_pynetbox_con.return_value.ipam.services.create.call_count == 0
    assert mock_pynetbox_con.return_value.ipam.services.update.call_count == 0



def test_netboxhandler_duplicated_ip(caplog, mock_pynetbox_con):
    ip = Ip("127.0.0.1/32")
    ip2 = Ip("127.0.0.1/32")
    with caplog.at_level(logging.WARNING):
        nb = NetBoxHandler("http://test:8000", "1234", False, "test_tag", False)
        nb.all_ips = [ip, ip2]
        nb.run({"127.0.0.1": {}})
        assert [True for record in caplog.records if record.message == 'Found 127.0.0.1 duplicated, skipping']
