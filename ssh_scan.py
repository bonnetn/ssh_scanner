#!/usr/bin/env python3

import argparse
import logging
import subprocess
from concurrent.futures.thread import ThreadPoolExecutor
from ipaddress import ip_network


def get_logger():
    logger = logging.getLogger("ssh_scanner")
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


def get_certificate(addr, timeout):
    logger.debug("Checking cert {}".format(addr))
    with subprocess.Popen(["ssh-keyscan", "-t", "rsa", "-T", str(timeout), str(addr)],
                          stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL) as proc:
        crt = proc.stdout.read()

    if not crt:
        logger.debug("No certificate found for {}".format(addr))
        return None, addr

    crt = crt.split()
    crt = crt[-1]
    crt = crt.decode()

    logger.debug("Got certificate for {}".format(addr))

    return crt, addr


def get_all_certs(executor, ip_range, timeout):
    addr_cert = executor.map(lambda addr: get_certificate(addr, timeout), ip_range)
    addr_cert = filter(lambda x: x[0], addr_cert)  # Remove hosts that have no certs
    return dict(addr_cert)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Scan for a host that has SSH enabled in two networks.')
    parser.add_argument('network1', type=str, action='store', help='network1')
    parser.add_argument('network2', type=str, action='store', help='network2')
    parser.add_argument('--timeout', type=int, action='store', default=5,
                        help='timeout expressed in seconds for each certificate request')
    args = parser.parse_args()

    timeout = args.timeout
    logger = get_logger()

    with ThreadPoolExecutor(max_workers=64) as executor:
        lan1_addr_cert = get_all_certs(executor, ip_network(args.network1), timeout)
        lan2_addr_cert = get_all_certs(executor, ip_network(args.network2), timeout)

    certs_in_both_networks = set(lan1_addr_cert.keys()) & set(lan2_addr_cert.keys())
    for cert in certs_in_both_networks:
        addr1 = lan1_addr_cert[cert]
        addr2 = lan2_addr_cert[cert]
        logger.info("{} = {} is SSHable in both networks.".format(addr1, addr2))
