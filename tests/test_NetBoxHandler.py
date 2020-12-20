import unittest
from unittest.mock import Mock, patch
import nose2

from modules.NetBoxHandler import NetBoxHandler

class MyTestCase(unittest.TestCase):
    def test_run(self):
        nb = NetBoxHandler("http://localhost","12345",True,"sync",False)
        response = nb.nb_version
        nose2. assert_is_not_none(response)


if __name__ == '__main__':
    unittest.main()
