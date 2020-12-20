import logging
import pynetbox
import requests


class NetBoxHandler:
    def __init__(self, url, token, tls_verify, tag, cleanup_allowed):
        self.url = url
        self.token = token
        self.tls_verify = not tls_verify
        self.tag = tag
        self.cleanup_allowed = cleanup_allowed
        self.nb_con = self.connect()
        self.nb_ver = self.get_version()

    def connect(self):
        session = requests.Session()
        session.verify = self.tls_verify
        nb_con = pynetbox.api(self.url, self.token)
        nb_con.http_session = session
        return nb_con

    def get_version(self):
        try:
            return self.nb_con.version
        except (ConnectionRefusedError, requests.exceptions.MissingSchema):
            logging.critical("Wrong URL or TOKEN, please check your config")
            exit(1)

    def run(self):
        logging.info(self.nb_ver)
