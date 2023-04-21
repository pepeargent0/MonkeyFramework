import pytest
from scapy.all import *
from scapy.layers.l2 import ARP
from scapy.layers.inet import IP
from scapy.sendrecv import sniff

from attack.leyer_2.mac import mac_flooding
from utils.interface import create_virtual_interface, delete_virtual_interface
import psutil


def stop_mac_flooding(iface: str):
    for proc in psutil.process_iter():
        try:
            pinfo = proc.as_dict(attrs=['pid', 'cmdline'])
        except psutil.NoSuchProcess:
            pass
        else:
            if pinfo['cmdline'] is not None and f"sendp(Ether(dst='{iface}')" in ' '.join(pinfo['cmdline']):
                proc.kill()


def test_mac_flooding_variability():
    # create virtual interface for testing
    iface = "test-25"
    create_virtual_interface(iface)

    # start MAC flooding attack
    mac_flooding(iface)

    # send packets to the virtual interface and check if they are received
    received_packets = []
    for i in range(10):
        mac_dst = RandMAC()
        packet = Ether(dst=mac_dst, src="11:11:22:33:44:55")
        sendp(packet, iface=iface)
        time.sleep(random.uniform(0.05, 0.15))  # introduce variability in packet sending times
        packets = sniff(iface=iface, count=1, filter="ether dst " + str(mac_dst), timeout=1)
        if len(packets) > 0:
            received_packets.append(packets[0].dst)

    assert len(received_packets) > 0, "No packets were received on virtual interface"
    assert all(mac == received_packets[0] for mac in
               received_packets), "Received packets with different destination MAC addresses"

    # stop MAC flooding attack and delete virtual interface
    stop_mac_flooding()
    delete_virtual_interface(iface)

