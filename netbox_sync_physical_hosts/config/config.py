import logging
import os
import configargparse


def parse_config():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    p = configargparse.ArgParser(default_config_files=[os.path.join(current_dir,
                                                                    'netbox-sync.conf')])

    p.add('-c', '--config', default=os.path.join(current_dir, 'netbox-sync.conf'),
          is_config_file=True,
          help="Config file path")

    p.add('-u', '--nb_url', required=True, env_var='NETBOX_URL', help="Netbox URL")

    p.add('-l', help='log level', default=logging.INFO,
          env_var='LOG_LEVEL')

    p.add('-p', '--nb_token', required=True, help="Token for Netbox connection",
          env_var='NETBOX_TOKEN')

    p.add('-x', '--nb_ignore-tls-errors', action='store_true',
          help="Ignore TLS conection errors")

    p.add('-f', '--cleanup', action='store_true', help="Cleanup orphans")

    p.add('-t', '--tag', help="Tag to use for device identification", env_var="TAG")

    p.add('-n', '--networks', required=True, help="Networks/Hosts to scan",
          env_var="NETWORKS")

    p.add('-o', '--get_mac', action='store_true', default=False,
          help="Enable if you want the script to try to collect MAC addresses/vendor",
          env_var="MAC_DISCOVER")

    p.add('-s', '--get_services', action='store_true', default=False,
          help="Enable if you want the script to discover host services",
          env_var="SERVICE_DISCOVER")

    conf = p.parse_args()
    logging.basicConfig(level=conf.l)

    return conf
