#!/usr/bin/env python3

import argparse
import logging
import subprocess
import sys
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


def validate_args(logger, args):
    timeout = args.timeout
    if timeout <= 0:
        logger.error("Timeout must be > 0.")
        sys.exit(1)

    parallel = args.parallel
    if parallel <= 0:
        logger.error("Parallel must be > 0.")
        sys.exit(1)

    try:
        network1 = ip_network(args.network1)
    except ValueError:
        logger.error("Network1 is invalid ({}).".format(args.network1))
        sys.exit(1)

    try:
        network2 = ip_network(args.network2)
    except ValueError:
        logger.error("Network2 is invalid ({}).".format(args.network2))
        sys.exit(1)

    return timeout, parallel, network1, network2


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Scan for a host that has SSH enabled in two networks.')
    parser.add_argument('network1', type=str, action='store', help='network1')
    parser.add_argument('network2', type=str, action='store', help='network2')
    parser.add_argument('--parallel', type=int, action='store', default=64,
                        help='number of scanning processes being run in parallel (default 64)')

    parser.add_argument('--timeout', type=int, action='store', default=5,
                        help='timeout expressed in seconds for each certificate request')
    args = parser.parse_args()

    logger = get_logger()
    timeout, parallel, network1, network2 = validate_args(logger, args)

    with ThreadPoolExecutor(max_workers=args.parallel) as executor:
        lan1_addr_cert = get_all_certs(executor, network1, timeout)
        lan2_addr_cert = get_all_certs(executor, network2, timeout)

    certs_in_both_networks = set(lan1_addr_cert.keys()) & set(lan2_addr_cert.keys())
    for cert in certs_in_both_networks:
        addr1 = lan1_addr_cert[cert]
        addr2 = lan2_addr_cert[cert]
        logger.info("{} = {} is SSHable in both networks.".format(addr1, addr2))
