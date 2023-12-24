"""from discover.arp_discover import arp_discover
from scanner.tcp import scanner_tcp

ip = '192.168.1.11'
mask = 24
for host in arp_discover(ip_addr=ip, mask=mask):
    host_tmp = scanner_tcp(host)
    print(host_tmp)"""

import os

from protocols.redis import RDIClient

rdi_client = RDIClient(server="your_rdp_server", username="your_username", password="your_password")

try:
    rdi_client.connect()
    # Do something with the connected RDP session

finally:
    rdi_client.disconnect()
