from typing import Generator
from multiprocessing import Pool
from dataclasses import dataclass
from scapy.all import ARP, Ether, srp, conf, get_if_hwaddr

conf.promisc = True


@dataclass
class DiscoverARP:
    ip: str
    mac: str


def process_packet(packet):
    send, received = packet
    return DiscoverARP(ip=received.psrc, mac=received.hwsrc)


def arp_discover(ip_addr: str = '127.0.0.1', mask: int = 24, timeout: float = 2, processes: int = 4) \
        -> Generator[DiscoverARP, None, None]:
    arp = ARP(pdst=ip_addr + '/' + str(mask))
    ether = Ether(dst="ff:ff:ff:ff:ff:ff", src=get_if_hwaddr(conf.iface))
    packet = ether / arp
    discovered_ips = set()
    with Pool(processes=processes) as pool:
        for host in pool.imap_unordered(process_packet, srp(packet, timeout=timeout, verbose=0)[0]):
            if host.ip not in discovered_ips:
                discovered_ips.add(host.ip)
                yield host

