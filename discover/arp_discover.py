from dataclasses import dataclass

from scapy.all import ARP, Ether, srp,ls
from typing import Iterable


@dataclass
class DiscoverARP:
    ip: str
    mac: str
    mac_dst: str
    def __post_init__(self):
        self._types = {"ip": str, "mac": str}


def arp_discover(ip_addr: str = '127.0.0.1', mask: str = 24) -> Iterable[DiscoverARP]:
    arp = ARP(pdst=ip_addr + '/' + str(mask))
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    hosts = srp(packet, timeout=4, verbose=0)[0]
    discovered_hosts = []
    for send, received in hosts:
        discovered_hosts.append(
            DiscoverARP(
                ip=received.psrc,
                mac=received.hwdst,
                mac_dst=received.hwsrc
            )
        )
    print(discovered_hosts)
    return discovered_hosts
