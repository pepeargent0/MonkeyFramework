from typing import Generator, List, Tuple, Optional
from multiprocessing import Pool, cpu_count
from dataclasses import dataclass
from ipaddress import ip_network
import warnings

# Silenciar solo el warning de Cryptography (no crítico)
try:
    from cryptography.utils import CryptographyDeprecationWarning
    warnings.filterwarnings(
        "ignore",
        category=CryptographyDeprecationWarning,
        module=r"scapy\.layers\.ipsec"
    )
except Exception:
    pass

from scapy.all import ARP, Ether, srp, conf, get_if_hwaddr, get_if_list

conf.verb = 0
conf.promisc = True
conf.sniff_promisc = False
conf.checkIPaddr = False


@dataclass
class DiscoverARP:
    ip: str
    mac: str


def _scan_subnet(args: Tuple[str, float, str]) -> List[DiscoverARP]:
    """Ejecuta srp() sobre un bloque pequeño de IPs usando la interfaz indicada."""
    subnet, timeout, iface = args
    ether = Ether(dst="ff:ff:ff:ff:ff:ff", src=get_if_hwaddr(iface))
    arp = ARP(pdst=subnet)
    packet = ether / arp

    answered, _ = srp(packet, timeout=timeout, inter=0.001, verbose=0, iface=iface)
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
    processes: Optional[int] = None,
    chunk_prefix: int = 28,
    iface: Optional[str] = None,
) -> Generator[DiscoverARP, None, None]:
    """
    Descubre dispositivos vía ARP dividiendo la red en sub-bloques.
    Requiere que el usuario especifique la interfaz activa.
    """
    if iface is None:
        raise ValueError(
            f"⚠️ Debes especificar la interfaz de red (por ejemplo: en0, eth0). "
            f"Interfaces disponibles: {', '.join(get_if_list())}"
        )

    conf.iface = iface
    net = ip_network(f"{ip_addr}/{mask}", strict=False)
    blocks = [str(sub) for sub in net.subnets(new_prefix=chunk_prefix)]
    processes = processes or min(cpu_count(), len(blocks))

    with Pool(processes=processes) as pool:
        for block_result in pool.imap_unordered(_scan_subnet, [(b, timeout, iface) for b in blocks]):
            for host in block_result:
                yield host
