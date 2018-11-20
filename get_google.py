#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import requests
from bs4 import BeautifulSoup


def gen_range(asn):
    cidr_range = list()
    link = 'https://ipinfo.io/' + asn
    try:
        response = requests.get(link, timeout=10)
    except Exception:
        response = None
    try:
        if response is None:
            requests.get(link, timeout=10, proxies={'https': 'socks://127.0.0.1:1080'})
    except Exception:
        raise Exception("Can not access https://ipinfo.io please check your network!")
    html = BeautifulSoup(response.content, "html.parser")
    table = html.find(id='block-table')
    if table:
        for tr in table.find_all('tr'):
            tds = tr.find_all('td')
            if tds:
                cidr_range.append(tds[0].text.replace(' ','').replace('\n', '').replace('\t', ''))
    return cidr_range


def gen_iptables_cmd(cidr_range, before='sudo', jump='REDIRECT', target_host='127.0.0.1', target_port='12345'):
    # type:(list) -> list
    u"""
    sudo iptables -t nat -A OUTPUT -p tcp -d 216.58.193.0/24  -j DNAT --to-destination 127.0.0.1:12345
    sudo iptables -t nat -A OUTPUT -p tcp -d 216.58.193.0/24 -j REDIRECT --to-ports 12345
    """
    execute_cmd_list = list()
    for cidr in cidr_range:
        if jump == 'REDIRECT':
            cmd = (before, 'iptables', '-t nat', '-A OUTPUT', '-p tcp', '-d', cidr, '-j REDIRECT',
                   '--to-ports', target_port)
        elif jump == 'DNAT':
            cmd = (before, 'iptables', '-t nat', '-A OUTPUT', '-p tcp', '-d', cidr, '-j DNAT',
                   '--to-destination', '{0}:{1}'.format(target_host, target_port))
        else:
            raise ValueError('Not support `%s`' % jump)
        execute_cmd_list.append(cmd)
    return execute_cmd_list


def generate_bash_script(file_name):
    # type:(str) -> None
    cmd_list = gen_iptables_cmd(gen_range('AS32934') + gen_range('AS15169') + gen_range('AS36351'))
    bash_file = ["#!/bin/bash\n"]
    for cmd in cmd_list:
        bash_file.append(' '.join(cmd) + '\n')

    with open(file_name, 'w') as script:
        script.writelines(bash_file)
    os.chmod(file_name, 0o0755)


if __name__ == '__main__':
    generate_bash_script("google.sh")
