from unittest.mock import MagicMock
from NmapHandler import NmapBasic, NmapMacScan, NmapServiceScan
import pytest

basic_result = {
    'stats': {'scanner': 'nmap', 'args': 'test', 'start': '1609858372',
              'startstr': 'Tue Jan  1 14:52:52 1988', 'version': '7.40',
              'xmloutputversion': '1.04'
              },
    'runtime': {'time': '1609858372', 'timestr': 'Tue Jan  1 14:52:52 1988', 'elapsed': '0.01',
                'summary': 'Nmap done at Tue Jan  5 14:52:52 2021; 1 IP address (1 host up) scanned in 0.01 seconds',
                'exit': 'success'
                }
}
service_result = {'127.0.0.1': {'osmatch': {}, 'ports':
                          [{'protocol': 'tcp', 'portid': '22', 'state': 'open', 'reason': 'syn-ack', 'reason_ttl': '0',
                            'service':
                                {'name': 'ssh', 'product': 'OpenSSH', 'version': '7.4p1 Debian 10+deb9u7',
                                 'extrainfo': 'protocol 2.0', 'ostype': 'Linux', 'method': 'probed', 'conf': '10'},
                            'cpe': [{'cpe': 'cpe:/o:linux:linux_kernel'}], 'scripts': []},
                           {'protocol': 'tcp', 'portid': '80', 'state': 'open', 'reason': 'syn-ack', 'reason_ttl': '0',
                            'service': {'name': 'http', 'product': 'lighttpd', 'method': 'probed', 'conf': '10'},
                            'cpe': [{'cpe': 'cpe:/a:lighttpd:lighttpd'}], 'scripts': []},
                           {'protocol': 'tcp', 'portid': '443', 'state': 'open', 'reason': 'syn-ack', 'reason_ttl': '0',
                            'service': {'name': 'http', 'product': 'lighttpd', 'tunnel': 'ssl', 'method': 'probed',
                                        'conf': '10'},
                            'cpe': [{'cpe': 'cpe:/a:lighttpd:lighttpd'}], 'scripts': []}], 'hostname': [],
                                       'macaddress': None,
                                       'state': {'state': 'up', 'reason': 'syn-ack', 'reason_ttl': '0'}},
                       'stats': {'scanner': 'nmap', 'args': '/usr/local/bin/nmap -oX - -sV -F -T4 192.168.4.1',
                                 'start': '1609901261', 'startstr': 'Wed Jan  6 02:47:41 2021', 'version': '7.40',
                                 'xmloutputversion': '1.04'},
                       'runtime': {'time': '1609901291', 'timestr': 'Wed Jan  6 02:48:11 2021', 'elapsed': '30.27',
                                   'summary': 'Nmap done at Wed Jan  6 02:48:11 2021; 1 IP address (1 host up) scanned in 30.27 seconds',
                                   'exit': 'success'}}


def create_result_dicts(add_dict: str):
    options = {
        'simple_one_host': {
            '127.0.0.1': {'osmatch': {}, 'ports': [],
                          'hostname': [{'name': 'localhost', 'type': 'PTR'}],
                          'macaddress': None,
                          'state': {'state': 'up', 'reason': 'mock-test', 'reason_ttl': '0'}
                          }
        },
        'simple_one_host_noDNS': {
            '127.0.0.1': {'osmatch': {}, 'ports': [],
                          'hostname': [],
                          'macaddress': None,
                          'state': {'state': 'up', 'reason': 'mock-test', 'reason_ttl': '0'}
                          }
        },
        'simple_one_host_mac': {
            '1.1.1.1': {'osmatch': {}, 'ports': [],
                        'hostname': [{'name': 'localhost', 'type': 'PTR'}],
                        'macaddress': "00:00:00:00:00",
                        'state': {'state': 'up', 'reason': 'mock-test', 'reason_ttl': '0'}
                        }
        },
        'simple_one_host_service': {
            '127.0.0.1': {'osmatch': {}, 'ports': [],
                          'hostname': [{'name': 'localhost', 'type': 'PTR'}],
                          'macaddress': None,
                          'state': {'state': 'up', 'reason': 'mock-test', 'reason_ttl': '0'}
                          }
        },
    }
    fake_result = dict()
    fake_result.update(basic_result)
    fake_result.update(options[add_dict])
    return fake_result


def aux_mockportscan(monkeypatch, dict_mock):
    mock_result = MagicMock(return_value=create_result_dicts(dict_mock))
    monkeypatch.setattr('nmap3.NmapHostDiscovery.nmap_no_portscan', mock_result)
    return mock_result

def test_nmapbasicobjectrun(monkeypatch):
    aux_mockportscan(monkeypatch, "simple_one_host")
    nmap = NmapBasic("test")
    nmap.run()
    assert nmap.scan_results == {'127.0.0.1': {'macaddress': None, 'subnet': 'test', 'dns_name': 'localhost'}}


def test_nohostname(monkeypatch):
    aux_mockportscan(monkeypatch, "simple_one_host_noDNS")
    nmap = NmapBasic("test")
    nmap.run()
    assert nmap.scan_results == {'127.0.0.1': {'macaddress': None, 'subnet': 'test'}}


@pytest.fixture()
def nmapscanrun_aux(monkeypatch):
    aux_mockportscan(monkeypatch, "simple_one_host_mac")
    mock_mac_vendor_update = MagicMock()
    monkeypatch.setattr("mac_vendor_lookup.MacLookup.update_vendors", mock_mac_vendor_update)
    return mock_mac_vendor_update


def test_nmapmacscanrun(monkeypatch, nmapscanrun_aux):
    mock_mac_vendor_lookup = MagicMock(return_value='testVendor')
    monkeypatch.setattr("mac_vendor_lookup.MacLookup.lookup", mock_mac_vendor_lookup)
    nmap = NmapMacScan("testMac")
    nmap.run()
    assert nmap.scan_results['1.1.1.1']["vendor"] == 'testVendor'


def test_nmapmacscanrun_nomac(monkeypatch, nmapscanrun_aux):
    mock_mac_vendor_lookup = MagicMock(return_value=None)
    monkeypatch.setattr("mac_vendor_lookup.MacLookup.lookup", mock_mac_vendor_lookup)
    nmap = NmapMacScan("testMac")
    nmap.run()
    assert not nmap.scan_results['1.1.1.1']["vendor"]


def test_nmapservicescanrun(monkeypatch):
    aux_mockportscan(monkeypatch, "simple_one_host_service")
    mock_result = MagicMock(return_value=service_result)
    monkeypatch.setattr('nmap3.Nmap.nmap_version_detection', mock_result)
    nmap = NmapServiceScan("test")
    nmap.run()
