import logging
import pynetbox
import requests


def get_host_by_ip(nb_ip):
    try:
        if nb_ip and nb_ip.assigned_object:
            logging.info(f"{nb_ip}: Host found => {nb_ip.assigned_object.device.name}")
            return nb_ip.assigned_object.device
    except AttributeError:
        logging.critical("You can only get host from a NB ip object")
        exit(1)


class NetBoxHandler:
    def __init__(self, url, token, tls_verify, tag, cleanup_allowed):
        self.url = url
        self.token = token
        self.tls_verify = not tls_verify
        self.tag = tag
        self.cleanup_allowed = cleanup_allowed
        self.nb_con = self.connect()
        self.nb_ver = self.get_version()
        #Netbox objects
        logging.info("Caching all Netbox data")
        self.all_ips = self.nb_con.ipam.ip_addresses.all()
        self.all_interfaces = self.nb_con.dcim.interfaces.all()
        self.all_devices = self.nb_con.dcim.devices.all()
        self.all_sites = self.nb_con.dcim.sites.all()
        self.TYPE_MAP = {
            "ip-addresses": self.all_ips,
            "interfaces": self.all_interfaces,
            "devices": self.all_devices,
            "sites": self.all_sites
        }
        #Netbox pre-reqs
        self.pre_reqs()

    def connect(self):
        session = requests.Session()
        session.verify = self.tls_verify
        nb_con = pynetbox.api(self.url, self.token, threading=True)
        nb_con.http_session = session
        return nb_con

    def get_version(self):
        try:
            return self.nb_con.version
        except (ConnectionRefusedError, requests.exceptions.MissingSchema):
            logging.critical("Wrong URL or TOKEN, please check your config")
            exit(1)

    def pre_reqs(self):
        if float(self.nb_ver) >= 2.9:
            self.tag = self.create_tag()

    def create_tag(self):
        scripttag = self.nb_con.extras.tags.get(name=self.tag)
        if not scripttag:
            logging.info("First run on Netbox instance, creating tag")
            scripttag = self.nb_con.extras.tags.create({"name": self.tag,
                                                          "slug": self.tag,
                                                          "description": f"Created by {__file__.split('/')[-3]}",
                                                          "color": '2196f3'})
            logging.debug(f"Tag {self.tag} created!")

        return scripttag.id

    def set_ip_attribute(self, ip, ip_attr):
        mask = ip_attr.get("subnet").split('/')[-1]
        nb_attr = {
            "address": f"{ip}/{mask}",
            "tags": [self.tag],
            "dns_name": ip_attr.get("dns_name",""),
            "description": ip_attr.get("description","")
        }
        return nb_attr

    def lookup_nb_obj(self, nb_obj):
        return [n for n in self.TYPE_MAP[nb_obj.endpoint.name] if nb_obj.name == n.name]

    def lookup_str_obj(self, obj, endpoint):
        return [n for n in self.TYPE_MAP[endpoint] if obj == n.name]

    def lookup_ip_address(self, ip):
        nb_ip = [nb_ip for nb_ip in self.TYPE_MAP["ip-addresses"] if nb_ip.address.startswith(f"{ip}/")]
        if not nb_ip:
            return None, True
        if len(nb_ip) == 1:
            return nb_ip[0], True
        else:
            return nb_ip, False

    def run(self, scanned_hosts):
        logging.debug(f"Netbox version: {self.nb_ver}")
        for ip, attr in scanned_hosts.items():
            nb_ip, single = self.lookup_ip_address(ip)
            if not single:
                logging.warning(f"Found {ip.address} duplicated")
            if nb_ip:
                nb_host = get_host_by_ip(nb_ip)
                if not nb_host:
                    logging.debug(f"Not host found for {ip}")
                else:
                    # TODO: Check what to do
                    logging.debug(f"Found host: {nb_host} with ip {ip}")
            else:
                logging.debug(f"{ip}: Not found in Netbox, creating record")
                logging.debug(self.nb_con.ipam.ip_addresses.create(self.set_ip_attribute(ip, attr)))
                logging.info(f"Record {ip} created")

