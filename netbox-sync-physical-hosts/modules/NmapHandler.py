import logging
import nmap3
from mac_vendor_lookup import MacLookup
from getmac import get_mac_address


class NmapBasic(object):
    def __init__(self, networks):
        self.hosts = dict()
        self.nmap = nmap3.NmapHostDiscovery()
        self.networks = self.sanitaise_networks(networks)
        self.scan_results = self.basic_scan()

    @staticmethod
    def sanitaise_networks(networks):
        networks = networks.split(',')
        for index, item in enumerate(networks):
            networks[index] = item.replace('\n', '')
        return networks

    def basic_scan(self):
        logging.info(f"Start NMAP scan for {self.networks}")
        for item in self.networks:
            self.scan_results = self.nmap.nmap_no_portscan(item,
                                                           args="-R --system-dns")
            self.scan_results.pop("stats")
            self.scan_results.pop("runtime")
            for host, v in self.scan_results.items():
                self.scan_results[host]["subnet"] = item
                self.sanitaise_dict(host)
        return self.scan_results

    def sanitaise_dict(self, host):
        """
        Remove unused dictionary entries
        :return: None
        """
        self.scan_results[host].pop("state")
        self.scan_results[host].pop("ports")
        self.scan_results[host].pop("osmatch")
        if self.scan_results[host]["hostname"]:
            self.scan_results[host]["dns_name"] = self.scan_results[host]["hostname"][0]["name"]
            self.scan_results[host].pop("hostname")
        else:
            self.scan_results[host].pop("hostname")

    def run(self):
        return self.scan_results


class NmapMacScan(NmapBasic):
    def __init__(self, networks, unknown="unknown"):
        super().__init__(networks)
        self.unknown = unknown
        self.mac_search = MacLookup()

    def update_mac(self, ip):
        """
        Update Mac info
        :param ip: IP address (ie: 192.168.1.1)
        :return: True if MAC is found, False otherwise
        """
        mac = get_mac_address(ip=ip, network_request=True)
        if mac is None:
            return False
        else:
            self.scan_results[ip]["macaddress"] = mac
            return True

    def update_vendor(self, ip):
        """
        Update MAC vendor if Mac is found
        :param ip: IP address (ie: 192.168.1.1)
        :return: None
        """
        logging.debug("Updating MAC table")
        self.mac_search.update_vendors()
        try:
            vendor_fetch = self.mac_search.lookup(self.scan_results[ip]["macaddress"])
            self.scan_results[ip]["vendor"] = vendor_fetch
        except KeyError:
            pass

    def correct_missing_mac(self, host):
        """
        Correct description if macaddress is not found
        :param host: host key in scan_results
        :return: None
        """
        if not self.scan_results[host]["macaddress"]:
            self.scan_results[host]["description"] = self.unknown
            self.scan_results[host].pop("macaddress")

    def scan(self):
        """
        Scan defined networks and conditionally check for mac vendor
        :return: scan_results = list()
        """
        for host, v in self.scan_results.items():
            if v.get("macaddress") or self.update_mac(host):
                self.update_vendor(ip=host)
            self.correct_missing_mac(host)
        return self.scan_results

    def run(self):
        return self.scan()


class NmapServiceScan(NmapBasic):
    def __init__(self, networks):
        super().__init__(networks)
        self.nmap = nmap3.Nmap()
        self.services = dict()

    def scan_service(self, host):
        # TODO: Investigate more if this can be parallelize
        logging.debug(f"Scan started for host: {host}")
        self.services[host] = self.nmap.nmap_version_detection(host, args="-F -T4")

    def scan(self):
        logging.info(f"Starting Service scan for hosts in {self.networks}")
        for host in self.scan_results:
            self.scan_service(host)
        self.append_service_results()
        return self.scan_results

    def append_service_results(self):
        self.sanitaise_services()
        for host, value in self.services.items():
            self.scan_results[host]["services"] = {}
            for service in value:
                try:
                    self.scan_results[host]["services"][service['portid']] = service
                except TypeError:
                    pass

    def sanitaise_services(self):
        for host, value in self.services.items():
            try:
                self.services[host] = value[host]["ports"]
            except KeyError:
                logging.debug(f"No services detected for {host}")
                continue
            for service in self.services[host]:
                try:
                    service.pop("reason")
                    service.pop("reason_ttl")
                    service.pop("cpe")
                    service.pop("scripts")
                    service["service"].pop("method")
                    service["service"].pop("conf")
                except KeyError:
                    pass

    def run(self):
        return self.scan()
