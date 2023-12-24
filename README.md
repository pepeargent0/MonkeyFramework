# MonkeyFramework

## instalacion
```
git clone https://github.com/pepeargent0/MonkeyFramework
cd MonkeyFramework
pip install -r requirements.txt
```
### COMO SE USA
```
se crea un archivo .py
y luego se ejecuta como root, esto se debe a 
que mucho porque se usan paquetes raw que solo se puede 
crear siendo root
```

### ARP DISCOVER
```
from discover.arp_discover import arp_discover

ip = '192.168.1.11'
mask = 24
for host in arp_discover(ip_addr=ip, mask=mask):
    print(host)
```

### PORT SCANNER
```
from discover.arp_discover import arp_discover
from scanner.tcp import scanner_tcp
ip = '192.168.1.11'
mask = 24
for host in arp_discover(ip_addr=ip, mask=mask):
    host_tmp = scanner_tcp(host)
    print(host_tmp)
```


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

### SCRAPPER DIRECTORY
```
from discover.struture import Scrapper
_site = 'http://10.129.230.191'
_file = '/Users/pepeargentoo/directory-list-2.3-small.txt'
scrapper = Scrapper(_site)
scrapper.get_directorys(_file)
```
