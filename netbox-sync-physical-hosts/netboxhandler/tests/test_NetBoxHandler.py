import unittest
from distutils.version import StrictVersion
from unittest.mock import patch, MagicMock
import pynetbox
from pynetbox.core.api import Api
from NetBoxHandler import NetBoxHandler, get_host_by_ip


# NB Model classes
class Name:
    name = "test"


class Device:
    device = Name()


class Ip:
    assigned_object = Device()


class NetboxHandlerCase(unittest.TestCase):

    @patch('pynetbox.api')
    @patch.object(pynetbox.api, 'version', version='2.9')
    def test_api_response_mock(self, mock_api, mock_version):
        # Call the function, which will send a request to the server.
        con = Api("test")
        inst = mock_version.return_value
        inst.version = "2.9"
        mock_api.return_value = con
        response = NetBoxHandler("http://localhost:8000", "1234",
                                 False, "test", False)
        # Assert that the request-response cycle completed successfully.
        self.assertIsInstance(response, NetBoxHandler)
        self.assertEqual(response.nb_ver, "2.9")
        self.assertEqual(response.token, "1234")

    def test_get_hosts_by_api(self):
        # Test return object
        nb_ip = Ip()
        test, device_type = get_host_by_ip(nb_ip)
        # Assert that the request-response cycle completed successfully.
        self.assertIsInstance(test, Name)
        self.assertEqual(device_type,"device")


if __name__ == '__main__':
    unittest.main()
