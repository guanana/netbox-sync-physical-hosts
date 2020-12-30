from NetBoxHandler import NetBoxHandler
from NmapScan import Nmap
import configargparse
import logging

p = configargparse.ArgParser(default_config_files=['netbox-sync.conf'])
p.add('-c', '--config', default="netbox-sync.conf", is_config_file=True, help="Config file path")
p.add('-u','--nb_url', required=True, env_var='NETBOX_URL', help="Netbox URL")
p.add('-l', help='log level', default=logging.INFO, env_var='LOG_LEVEL')
p.add('-p', '--nb_token', required=True, help="Token for Netbox connection", env_var='NETBOX_TOKEN')
p.add('-x', '--nb_ignore-tls-errors', action='store_true', help="Ignore TLS conection errors")
p.add('-f', '--clenaup', action='store_true', help="Cleanup orphans")
p.add('-t', '--tag', help="Tag to use for device identification")
p.add('-n', '--networks', required=True, help="Networks/Hosts to scan", env_var="NETWORKS")
p.add('-o', '--get_mac', default=False, help="Enable if you want the script to try to collect MAC addresses/vendor",
      env_var="MAC")

conf = p.parse_args()
logging.basicConfig(level=conf.l)

if __name__ == '__main__':

    scanner = Nmap(conf.networks, conf.get_mac)
    hosts = scanner.run()
    nb = NetBoxHandler(conf.nb_url, conf.nb_token, conf.nb_ignore_tls_errors, conf.tag, conf.clenaup, hosts )
    nb.run()
    exit(0)
