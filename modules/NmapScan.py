import logging
import nmap3


class Nmap(object):

    def __init__(self, networks, os_detection, unknown="unknown"):
        self.unknown = unknown
        self.networks = networks.split(',')
        self.hosts = {}
        self.os_detection = os_detection
        self.scan_results = self.scan()

    def scan(self):
        nmap = nmap3.NmapHostDiscovery()  # instantiate nmap object
        logging.info(f"Start NMAP scan for {self.networks}")
        scan_results = {}
        for item in self.networks:
            if not self.os_detection:
                temp_scan_result = nmap.nmap_no_portscan(item.replace('\n', ''), args="-R --system-dns")
            else:
                if nmap.as_root:
                    temp_scan_result = nmap.nmap_os_detection(item.replace('\n', ''), args="-R --system-dns")
                else:
                    logging.critical("If you enable OS detection you must be root")
                    exit(1)
            scan_results = {**scan_results, **temp_scan_result}
            scan_results.pop("stats")
            scan_results.pop("runtime")
        return scan_results

    def run(self):
        for k,v in self.scan_results.items():
            try:
                self.hosts.update({k:{
                    "dns_name": v['hostname'][0]['name']
                }})
            except (IndexError, KeyError):
                 self.hosts.update({k:{
                    "description": self.unknown
                 }})
        print(self.hosts)
