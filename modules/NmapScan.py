import logging
import nmap3
from mac_vendor_lookup import MacLookup
from getmac import get_mac_address

class Nmap(object):

    def __init__(self, networks, get_mac, unknown="unknown"):
        self.unknown = unknown
        self.networks = networks.split(',')
        self.hosts = {}
        self.get_mac = get_mac
        self.mac_search = MacLookup()
        self.scan_results = self.scan()

    def scan(self):

        def update_mac(ip):
            """
            Update Mac info
            :param ip: IP address (ie: 192.168.1.1)
            :return: True if MAC is found, False otherwise
            """
            mac = get_mac_address(ip=ip, network_request=True)
            if mac is None:
                return False
            else:
                scan_results[ip]["macaddress"] = mac
                return True

        def update_vendor(ip):
            """
            Update MAC vendor if Mac is found
            :param ip: IP address (ie: 192.168.1.1)
            :return: None
            """
            logging.debug("Updating MAC table")
            self.mac_search.update_vendors()
            try:
                vendor_fetch = self.mac_search.lookup(scan_results[ip]["macaddress"])
                scan_results[ip]["vendor"] = vendor_fetch
            except KeyError:
                pass

        def sanitaise_dict():
            """
            Remove unused dictionary entries
            :return: None
            """
            scan_results[host].pop("state")
            scan_results[host].pop("ports")
            scan_results[host].pop("osmatch")
            if scan_results[host]["hostname"]:
                scan_results[host]["dns_name"] = scan_results[host]["hostname"][0]["name"]
                scan_results[host].pop("hostname")
            else:
                scan_results[host].pop("hostname")
            if not scan_results[host]["macaddress"]:
                scan_results[host]["description"] = self.unknown
                scan_results[host].pop("macaddress")

        nmap = nmap3.NmapHostDiscovery()  # instantiate nmap object
        logging.info(f"Start NMAP scan for {self.networks}")
        scan_results = {}
        for item in self.networks:
            temp_scan_result = nmap.nmap_no_portscan(item.replace('\n', ''), args="-R --system-dns")
            scan_results = {**scan_results, **temp_scan_result}
            scan_results.pop("stats")
            scan_results.pop("runtime")
        for host, v in scan_results.items():
            if self.get_mac:
                if update_mac(host):
                    update_vendor(ip=host)
            sanitaise_dict()

        return scan_results

    def run(self):
        return self.scan_results
