import sys
from config.config import parse_config
from netboxhandler.NetBoxHandler import NetBoxHandler
from modules.NmapHandler import NmapServiceScan, NmapMacScan, NmapBasic


def main(conf):
    nb = NetBoxHandler(conf.nb_url, conf.nb_token,
                       conf.nb_ignore_tls_errors, conf.tag, conf.cleanup)

    if conf.get_mac:
        nmap = NmapMacScan(conf.networks)
        hosts = nmap.run()
        nb.run(hosts)

    if conf.get_services:
        nmap = NmapServiceScan(conf.networks)
        hosts = nmap.run()
        nb.run(hosts)

    if not conf.get_mac and not conf.get_services:
        nmap = NmapBasic(conf.networks)
        hosts = nmap.run()
        nb.run(hosts)


if __name__ == '__main__':
    conf = parse_config()
    sys.exit(main(conf))

