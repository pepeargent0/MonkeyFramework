from discover.arp_discover import arp_discover

ip = '192.168.1.11'
mask = 24
for host in arp_discover(ip_addr=ip, mask=mask):
    print(host)
