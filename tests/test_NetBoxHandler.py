import unittest
from unittest.mock import patch, PropertyMock

import pynetbox
import requests
from pynetbox.core.api import Api

from netboxhandler.NetBoxHandler import NetBoxHandler, get_host_by_ip

#NB Model classes
class name:
    name = "test"
class device:
    device = name()
class ip:
    assigned_object = device

class NetboxHandlerCase(unittest.TestCase):

    @patch('pynetbox.api')
    @patch.object(pynetbox.api, 'version', version="2.9")
    #@patch.object(pynetbox, 'api', version="2.9")
    def test_api_response_mock(self, mock_api, mock_version):
        # Call the function, which will send a request to the server.
        con = Api("test")
        mock_api.return_value = con
        response = NetBoxHandler("http://localhost:8000", "0123456789abcdef0123456789abcdef01234567",
                                 False, "test", False, ({1: "test"},{2:"test"}))
        response.nb_ver = "2.9"
        # Assert that the request-response cycle completed successfully.
        self.assertIsInstance(response, NetBoxHandler)
        self.assertEqual(response.nb_ver, "2.9")
        self.assertEqual(response.token, "0123456789abcdef0123456789abcdef01234567")

    def test_get_hosts_by_api(self):
        # Test return object
        nb_ip = ip()
        test = get_host_by_ip(nb_ip)
        # Assert that the request-response cycle completed successfully.
        self.assertIsInstance(test, name)


if __name__ == '__main__':
    unittest.main()
