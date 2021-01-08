import logging
from distutils.version import StrictVersion
from pynetbox.core.query import RequestError as pynetbox_RequestError
import pynetbox
import requests
from django.utils.text import slugify


def get_host_by_ip(nb_ip):
    try:
        if nb_ip and hasattr(nb_ip.assigned_object, "device"):
            logging.info(f"{nb_ip}: Host found => "
                         f"{nb_ip.assigned_object.device.name}")
            return nb_ip.assigned_object.device, "device"
        elif nb_ip and hasattr(nb_ip.assigned_object, "virtual_machine"):
            logging.info(f"{nb_ip}: Virtual Host found => "
                         f"{nb_ip.assigned_object.virtual_machine.name}")
            return nb_ip.assigned_object.virtual_machine, "virtual_machine"
        else:
            return None, None
    except AttributeError:
        logging.critical("You can only get host from a NB ip object")
        exit(1)


class NetBoxHandler:
    def __init__(self, url, token, tls_verify, tag, cleanup_allowed):
        self.url = url
        self.token = token
        self.tls_verify = not tls_verify
        self.scripttag = tag
        self.cleanup_allowed = cleanup_allowed
        self.nb_con = self.nb_con()
        self.nb_ver = self.nb_ver()
        # Netbox objects
        logging.info("Caching all Netbox data")
        try:
            self.all_ips = self.nb_con.ipam.ip_addresses.all()
            self.all_interfaces = self.nb_con.dcim.interfaces.all()
            self.all_devices = self.nb_con.dcim.devices.all()
            self.all_sites = self.nb_con.dcim.sites.all()
            self.all_services = self.nb_con.ipam.services.all()
        except pynetbox_RequestError:
            logging.critical("Invalid token")
            exit(1)
        # Netbox pre-reqs
        self.pre_reqs()

    def nb_con(self):
        session = requests.Session()
        session.verify = self.tls_verify
        nb_con = pynetbox.api(self.url, self.token, threading=True)
        nb_con.http_session = session
        return nb_con

    def nb_ver(self):
        try:
            return StrictVersion(self.nb_con.version)
        except ConnectionRefusedError:
            logging.critical("Wrong URL or TOKEN, please check your config")
            exit(1)
        except requests.exceptions.MissingSchema:
            logging.critical(f"{self.url}: URL format should contain http or https")
            exit(1)
        except requests.exceptions.ConnectionError:
            logging.critical(f"{self.url}: Impossible to contact Netbox")
            exit(1)

    def pre_reqs(self):
        if self.nb_ver >= StrictVersion("2.9"):
            self.scripttag = self.create_tag(self.scripttag, scripttag=True)
        else:
            raise Exception("This script only works with Netbox > 2.9")

    def create_tag(self, tag, scripttag=False):
        nb_tag = self.nb_con.extras.tags.get(name=tag)
        if not nb_tag:
            if scripttag:
                logging.info("First run on Netbox instance, creating tag")
            nb_tag = self.nb_con.extras.tags.create(
                {"name": tag,
                 "slug": slugify(tag),
                 "description": f"Created by {__file__.split('/')[-3]}",
                 "color": '2196f3'}
            )
            logging.debug(f"Tag {tag} created!")

        return nb_tag

    def set_ip_attribute(self, ip, ip_attr):
        pre_mask = ip_attr.get("subnet").split('/')
        if len(pre_mask) == 2:
            mask = pre_mask[-1]
        else:
            logging.error(f"Problem with IP {ip}")
            return None
        nb_attr = {
            "address": f"{ip}/{mask}",
            "tags": [self.scripttag.id],
            "dns_name": ip_attr.get("dns_name", ""),
            "description": ip_attr.get("description", "")
        }
        return nb_attr

    def set_service_attribute(self, host, service, device_type, ip):
        nb_attr = {
            device_type: host.id,
            "name": service["service"]["name"],
            "description": f"{service['service'].get('product')}: "
                           f"{service['service'].get('version','version_unknown')}",
            "tags": [self.scripttag.id],
            "protocol": service["protocol"],
            "port": service["portid"],
            "ipaddresses": [ip.id]
        }
        return nb_attr

    def lookup_ip_address(self, ip):
        nb_ip = [nb_ip for nb_ip in self.all_ips if nb_ip.address.startswith(f"{ip}/")]
        if not nb_ip:
            return None, True
        if len(nb_ip) == 1:
            return nb_ip[0], True
        else:
            return nb_ip, False

    def lookup_service(self, host, service, device_type, ip):
        try:
            if device_type == "device":
                nb_service = [nb_service for nb_service in self.all_services
                              if nb_service.device == host and
                              nb_service.port == int(service["portid"]) and
                              [True for nb_ip in nb_service.ipaddresses
                               if nb_ip.id == ip["id"]]][0]
            else:
                nb_service = [nb_service for nb_service in self.all_services
                              if nb_service.virtual_machine == host and
                              nb_service.port == int(service["portid"]) and
                              [True for nb_ip in nb_service.ipaddresses
                               if nb_ip.id == ip["id"]]][0]
        except IndexError:
            return
        return nb_service

    def nb_create_ip(self, ip_attr):
        logging.debug(f"{ip_attr.get('address')}: Not found in Netbox, creating record")
        nb_ip = self.nb_con.ipam.ip_addresses.create()
        logging.info(f"Record {ip_attr.get('address')} created")
        return nb_ip

    def nb_create_service(self, service_attr):
        logging.debug(f"{service_attr.get('name')}: Creating service")
        nb_service = self.nb_con.ipam.services.create(service_attr)
        logging.info(f"Service {service_attr.get('name')} created")
        return nb_service

    def create_service(self, host, service, device_type, nb_ip):
        logging.info(f"Creating service {service['portid']}")
        service_attr = self.set_service_attribute(host, service, device_type, nb_ip)
        nb_service = self.lookup_service(host, service, device_type, nb_ip)
        if not nb_service:
            nb_service = self.nb_create_service(service_attr)
        else:
            for tag in nb_service.tags:
                if self.scripttag.id == tag.id:
                    nb_service.update(service_attr)
                    return nb_service
            logging.info(f"Service {service['portid']} "
                         f"found but scripttags is not present, "
                         f"skipping update")
        return nb_service

    def run(self, scanned_hosts):
        logging.debug(f"Netbox version: {self.nb_ver}")
        for ip, attr in scanned_hosts.items():
            nb_ip, single = self.lookup_ip_address(ip)
            if not single:
                logging.warning(f"Found {ip} duplicated, skipping")
                continue
            if nb_ip:
                nb_host, device_type = get_host_by_ip(nb_ip)
                if not nb_host:
                    logging.debug(f"Not host found for {ip}")
                    continue
                else:
                    if attr.get("services"):
                        for port, service in attr["services"].items():
                            self.create_service(nb_host, service, device_type, nb_ip)
                        logging.debug(f"Found ports: {nb_host} with ip {ip}")
                    # TODO: Check what to do
                    logging.debug(f"Found host: {nb_host} with ip {ip}")
            else:
                ip_attr = self.set_ip_attribute(ip, attr)
                if ip_attr:
                    self.nb_create_ip(ip_attr)
                else:
                    logging.error(f"Problem found, IP not created")
