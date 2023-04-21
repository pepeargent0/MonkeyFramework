from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

from discover.arp_discover import DiscoverARP
from utils.host import Host, Port
from scapy.all import IP, UDP, sr1


def scanner_udp(host: DiscoverARP, port: int = 1025) -> Host:
    open_ports = []
    with ThreadPoolExecutor() as executor:
        futures = [executor.submit(scan_port, host.ip, port) for port in range(1, port)]
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(Port(num=Port, ver=''))

    return Host(ip=host.ip, mac=host.mac, ports=open_ports, os='')


def scan_port(ip: str, port: int) -> int:
    packet = IP(dst=ip) / UDP(dport=port)
    response = sr1(packet, timeout=2, verbose=0)
    if response:
        return port
    else:
        return None
