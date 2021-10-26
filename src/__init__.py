"""
This module contains functions common to multiple scripts
"""
import ipaddress
import re
import socket
import subprocess
import sys

server_types = [
    "backup", "drive-idp-proxy", "fe-sto3-lb", "fe-sto4-lb", "gss",
    "gssbackup", "gss-db", "intern-db", "lb", "lookup", "lookupbackup",
    "lookup-db", "monitor", "multinode", "node", "script"
]


def build_fqdn(instance: str, environment: str, number: int) -> str:
    """build_fqdn for database server.

    :param instance:
    :type instance: str
    :param environment:
    :type environment: str
    :param number:
    :type number: int
    :rtype: str
    """
    basename = instance + '-db' + str(number)
    environ = '.' + environment + '.'

    if environment == 'prod':
        environ = '.'
    domain = '.drive' + environ + 'sunet.se'

    if instance not in ["gss", "lookup"]:
        domain = '.' + instance + domain
        basename = "intern-db" + str(number)

    return basename + domain


def compute_lb_node(fqdn: str) -> tuple[int, int]:
    """compute_lb_node.

    :param fqdn:
    :type fqdn: str
    :rtype: tuple[int, int]
    """
    summation = int()

    for char in fqdn:
        summation += ord(char)
    mhash = (summation % 2)
    lbs: tuple[int, int] = (1, 2)

    if mhash == 1:
        lbs = (3, 4)

    return lbs


def get_ips_for_hostname(hostname: str) -> tuple[list[str], list[str]]:
    """get_ips_for_hostname.

    :param hostname:
    :type hostname: str
    :rtype: tuple[list[str],list[str]]
    """
    ip_v4: list = list()
    ip_v6: list = list()
    try:
        ips: list[tuple] = socket.getaddrinfo(hostname, None)

        for addr in ips:
            address = addr[4][0]

            if is_ipv4(address) and address not in ip_v4:
                ip_v4.append(address)
            elif is_ipv6(address) and address not in ip_v6:
                ip_v6.append(address)

        ip_v4.sort()
        ip_v6.sort()
    except socket.gaierror:
        pass

    return (ip_v4, ip_v6)


def get_server_regex(data: dict) -> str:
    """get_server_regex.

    :param data:
    :type data: dict
    :rtype: str
    """

    if data['customer'] not in ["gss", "lookup", "common"]:
        customer = r'\.' + data['customer']
    else:
        customer = ''

    if data['environment'] == "prod":
        environment = ''
    else:
        environment = r'\.' + data['environment']
    suffix = environment + r'\.sunet\.se$'
    prefix = r'^' + data['server_type'] + r'[1-9]'

    if data['server_type'] in ["multinode"]:
        prefix = r'^' + data['fqdn'].split('.')[0]
    server_regex = prefix + customer + r'\.drive' + suffix

    return server_regex


def is_ipv4(addr: str) -> bool:
    """is_ipv4.

    :param addr:
    :type addr: str
    :rtype: bool
    """
    try:
        ipaddress.IPv4Network(addr)

        return True
    except ValueError:
        return False


def is_ipv6(addr: str) -> bool:
    """is_ipv6.

    :param addr:
    :type addr: str
    :rtype: bool
    """
    try:
        ipaddress.IPv6Network(addr)

        return True
    except ValueError:
        return False


def parse_fqdn(fqdn: str) -> dict:
    """parse_fqdn.

    :param fqdn:
    :type fqdn: str
    :rtype: dict
    """
    data = {}
    data['fqdn'] = fqdn
    type_regex = r'-*[1-9]*\..*'
    server_type = re.sub(type_regex, '', fqdn)

    if server_type not in server_types:
        print("Server type {} is not supported.".format(server_type))
        sys.exit(1)
    else:
        data['server_type'] = server_type

    env_regex = r'.*(pilot|test).*'
    data['environment'] = re.sub(env_regex, r'\1', fqdn)

    if data['environment'] not in ['pilot', 'test']:
        data['environment'] = 'prod'

    if server_type in ["backup", "intern-db", "node", "script"]:
        data['customer'] = fqdn.split('.')[1]
        data['common_dir'] = data['customer'] + '-common'
    elif server_type in ['gss', 'lookup']:
        data['customer'] = server_type
        data['common_dir'] = data['server_type'] + '-common'
    elif server_type == 'gssbackup':
        data['customer'] = 'gss'
        data['common_dir'] = 'gss-common'
    elif server_type == 'lookupbackup':
        data['customer'] = 'lookup'
        data['common_dir'] = 'lookup-common'
    else:
        data['customer'] = 'common'
        data['common_dir'] = data['server_type'] + '-common'

    if server_type == 'lb':
        data['common_dir'] = data['common_dir'] + '-' + data['environment']

    return data


def run_remote_command(fqdn, command: list) -> tuple:
    """run_remote_command.

    :param fqdn:
    :param command:
    :type command: list
    :rtype: tuple
    """
    base_command = ['ssh', '-o', 'StrictHostKeyChecking=off', fqdn]
    run_command = base_command + command
    with subprocess.Popen(run_command, stdout=subprocess.PIPE) as proc:
        outs, errs = proc.communicate()
    reply = outs.decode().strip('\n')

    return (reply, errs)
