from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue
from utils.host import Host, Port
from scapy.all import IP, TCP, conf, sr1
from discover.arp_discover import DiscoverARP

conf.verb = 0


def scan_port(ip: str, port: int, flags: str, queue: Queue):
    packet = IP(dst=ip) / TCP(dport=port, flags=flags)
    response = sr1(packet, timeout=1, verbose=0)
    if response and TCP in response and response[TCP].flags == 'SA':
        queue.put(Port(num=port, ver=''))


def scan_ports(host: DiscoverARP, flags: str, port: int = 1025) -> Host:
    queue = Queue()
    with ThreadPoolExecutor() as executor:
        args = ((host.ip, port, flags, queue) for port in range(1, port))
        futures = [executor.submit(scan_port, *arg) for arg in args]
        for future in as_completed(futures):
            future.result()
    open_ports = list(queue.queue)
    return Host(ip=host.ip, mac=host.mac, ports=open_ports, os='')


def scanner_tcp(host: DiscoverARP, port: int = 1025) -> Host:
    return scan_ports(host, 'S', port=port)


def scanner_syn(host: DiscoverARP, port: int = 1025) -> Host:
    return scan_ports(host, 'S', port=port)


def scanner_xmas(host: DiscoverARP, port: int = 1025) -> Host:
    return scan_ports(host, 'FPU', port=port)
