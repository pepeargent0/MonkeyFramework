from discover.arp_discover import arp_discover


if __name__ == "__main__":
    for h in arp_discover(ip_addr="192.168.0.0", mask=24, timeout=0.8, processes=8):
        print(h)