import unittest
run = __import__("run.py")


class MyTestCase(unittest.TestCase):
    def test_run(self):
        self.assertEqual(True, False)


if __name__ == '__main__':
    unittest.main()
