"""
This module contains functions common to multiple scripts
"""
import ipaddress
import re
import socket
import subprocess
import sys

import requests
import urllib3

urllib3.disable_warnings()

server_types = [
    "backup", "document", "document-be", "documentbackup", "drive-idp-proxy",
    "fe-sto3-lb", "fe-sto4-lb", "gss", "gssbackup", "gss-db", "idp-proxy", "intern-db",
    "lb", "lookup", "lookupbackup", "lookup-db", "kube", "monitor",
    "multinode", "multinode-db", "ni", "node", "resolve", "script"
]


def build_fqdn(instance: str,
               environment: str,
               number: int,
               server_type: str = "") -> str:
    """build_fqdn.

    :param instance:
    :type instance: str
    :param environment:
    :type environment: str
    :param number:
    :type number: int
    :param server_type:
    :type server_type: str
    :rtype: str
    """

    environ = '.' + environment + '.'

    if environment == 'prod':
        environ = '.'
    domain = '.drive' + environ + 'sunet.se'

    basename = instance + '-db' + str(number)

    if instance not in ["gss", "lookup", "multinode"]:
        domain = '.' + instance + domain
        basename = "intern-db" + str(number)

    if server_type:
        basename = server_type + str(number)

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

    if server_regex == r'^monitor[1-9]\.drive\.sunet\.se$':
        server_regex = r'^monitor\.drive\.sunet\.se$'
    elif server_regex == r'^drive-idp-proxy[1-9]\.drive\.sunet\.se$':
        server_regex = r'^drive-idp-proxy-[1-2]\.sunet\.se$'

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

        if data['customer'] == 'drive':
            data['customer'] = 'common'
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
    elif server_type in ['multinode-db','kube']:
        data['customer'] = 'common'
        data['common_dir'] = 'multinode-common'
    elif server_type in ['drive-idp-proxy', 'document']:
        data['customer'] = 'common'
        data['common_dir'] = 'common-common'
    else:
        data['customer'] = 'common'
        data['common_dir'] = data['server_type'] + '-common'

    if server_type == 'lb':
        data['common_dir'] = data['common_dir'] + '-' + data['environment']

    return data


def run_remote_command(fqdn: str,
                       command: list,
                       user: str = "root",
                       output=subprocess.PIPE) -> tuple:
    """run_remote_command.

    :param fqdn:
    :type fqdn: str
    :param command:
    :type command: list
    :param user:
    :type user: str
    :param output:
    :rtype: tuple
    """
    base_command = ['ssh', '-o', 'StrictHostKeyChecking=off', '-l', user, fqdn]
    run_command = base_command + command
    with subprocess.Popen(run_command, stdout=output, stderr=output) as proc:
        outs, errs = proc.communicate()
    try:
        reply = outs.decode().strip('\n')
    except AttributeError:
        reply = str()

    return (reply, errs)


def smoketest_backup_node(fqdn: str) -> bool:
    """smoketest_backup_node.

    :param fqdn:
    :type fqdn: str
    :rtype: bool
    """
    get_db_password = r"""grep MYSQL_ROOT_PASSWORD """
    get_db_password += r"""/opt/mariadb_backup/docker-compose.yml"""
    get_db_password += r""" | awk -F '=' '{print $2}'"""
    result = run_remote_command(fqdn, [get_db_password])
    status = "OFF"

    if not result[1]:
        db_password = result[0]
        mariadb_base = r'''docker exec mariadbbackup_mariadb_backup_1 mysql '''
        mariadb_base += r'''-u root -p'{}' -N -B -e '''.format(db_password)
        mariadb_base += r'''"show status like 'Slave_running'"'''
        status_result = run_remote_command(fqdn, [mariadb_base])

        try:
            status = status_result[0].split('\t')[1]
        except:
            return False

    return status == "ON"


def smoketest_db_cluster(fqdn: str) -> dict:
    """smoketest_db_cluster.

    :param fqdn:
    :type fqdn: str
    :rtype: dict
    """
    get_db_password = r"""grep MYSQL_ROOT_PASSWORD """
    get_db_password += r"""/opt/mariadb/docker-compose.yml"""
    get_db_password += r""" | awk -F '=' '{print $2}'"""
    result = run_remote_command(fqdn, [get_db_password])

    if not result[1]:
        data: dict = dict()
        db_password = result[0]
        mariadb_base = r'''docker exec mariadb_db_1 mysql '''
        mariadb_base += r'''-u root -p'{}' -N -B -e "show status like '{}'"'''
        sizetest = [mariadb_base.format(db_password, 'wsrep_cluster_size')]
        statustest = [mariadb_base.format(db_password, 'wsrep_cluster_status')]
        size_result = run_remote_command(fqdn, sizetest)
        status_result = run_remote_command(fqdn, statustest)

        try:
            data['size'] = size_result[0].split('\t')[1]
        except:
            return {'error': size_result[1]}

        try:
            data['status'] = status_result[0].split('\t')[1]
        except:
            return {'error': status_result[1]}

        return data
    else:
        return {'error': result[1]}


def smoketest_db_node(fqdn: str) -> bool:
    """smoketest_db_node.

    :param fqdn:
    :type fqdn: str
    :rtype: bool
    """

    data: dict = smoketest_db_cluster(fqdn)

    if "error" in data:
        return False

    return data['size'] == "3" and data['status'] == "Primary"


def smoketest_nextcloud_node(fqdn: str, port: str = "443") -> bool:
    """smoketest_nextcloud_node.

    :param fqdn:
    :type fqdn: str
    :param port:
    :type port: str
    :rtype: bool
    """
    status_url = "https://{}:{}/status.php".format(fqdn, port)
    try:
        req = requests.get(status_url, verify=False)
    except requests.exceptions.ConnectionError:
        return False

    if req.status_code != 200:
        return False
    data = req.json()

    if 'installed' not in data.keys():
        return False

    if 'maintenance' not in data.keys():
        return False

    if not data['installed']:
        return False

    if data['maintenance']:
        return False

    return True
