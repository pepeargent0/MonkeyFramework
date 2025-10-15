from typing import Generator, List, Tuple
from multiprocessing import Pool, cpu_count
from dataclasses import dataclass
from ipaddress import ip_network
from scapy.all import ARP, Ether, srp, conf, get_if_hwaddr

conf.verb = 0
conf.promisc = True
conf.sniff_promisc = False
conf.checkIPaddr = False


@dataclass
class DiscoverARP:
    ip: str
    mac: str


def _scan_subnet(args: Tuple[str, float]) -> List[DiscoverARP]:
    """Ejecuta srp() sobre un bloque pequeño de IPs."""
    subnet, timeout = args
    ether = Ether(dst="ff:ff:ff:ff:ff:ff", src=get_if_hwaddr(conf.iface))
    arp = ARP(pdst=subnet)
    packet = ether / arp

    answered, _ = srp(packet, timeout=timeout, inter=0.001, verbose=0)
    results = []
    seen = set()
    for _, recv in answered:
        ip, mac = recv.psrc, recv.hwsrc
        if ip not in seen:
            seen.add(ip)
            results.append(DiscoverARP(ip=ip, mac=mac))
    return results


def arp_discover(
    ip_addr: str = "192.168.0.0",
    mask: int = 24,
    timeout: float = 1.0,
    processes: int | None = None,
    chunk_prefix: int = 28,
) -> Generator[DiscoverARP, None, None]:
    """
    Descubre dispositivos vía ARP lo más rápido posible dividiendo la red en sub-bloques.
    """
    net = ip_network(f"{ip_addr}/{mask}", strict=False)
    blocks = [str(sub) for sub in net.subnets(new_prefix=chunk_prefix)]
    processes = processes or min(cpu_count(), len(blocks))

    with Pool(processes=processes) as pool:
        for block_result in pool.imap_unordered(_scan_subnet, [(b, timeout) for b in blocks]):
            for host in block_result:
                yield host
