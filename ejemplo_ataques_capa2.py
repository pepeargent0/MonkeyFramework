import os
import platform
from time import sleep

from scapy.arch import get_if_hwaddr

from attack.leyer_2.mac import mac_flooding, mac_spoofing, vendor_mac_attack, mac_duplication


def demo_macos_enhanced(iface: str = "en0"):
    """Demo optimizada para macOS con mejor manejo de errores"""
    system = platform.system()
    print(f"🚀 INICIANDO DEMO MEJORADA PARA {system.upper()}")
    print("=" * 60)

    current_mac = get_if_hwaddr(iface)
    print(f"📍 Sistema: {system}")
    print(f"📍 Interface: {iface}")
    print(f"📍 MAC actual: {current_mac}")

    if system == 'Darwin':
        print("\n💡 INFORMACIÓN macOS:")
        print("   • Para spoofing real: csrutil disable (Recovery Mode)")
        print("   • Algunos ataques funcionarán en modo simulación")
        print("   • Los ataques de flooding siempre funcionan")

    # 1. MAC Flooding (siempre funciona)
    print("\n" + "=" * 50)
    print("1. 🌊 MAC FLOODING (4 segundos)")
    print("=" * 50)
    flood_attack = mac_flooding(iface, packet_rate=400, duration=4, verbose=True)
    sleep(6)

    # 2. MAC Duplication (siempre funciona)
    print("\n" + "=" * 50)
    print("2. 🎭 MAC DUPLICATION (4 segundos)")
    print("=" * 50)
    dup_attack = mac_duplication(iface, "aa:bb:cc:dd:ee:ff", duration=4, verbose=True)
    sleep(6)

    # 3. Vendor MAC (puede funcionar en modo simulación)
    print("\n" + "=" * 50)
    print("3. 🏷️ VENDOR MAC ATTEMPT (5 segundos)")
    print("=" * 50)
    vendor_attack = vendor_mac_attack(iface, "apple", duration=5, verbose=True)
    sleep(7)

    # 4. MAC Spoofing individual
    print("\n" + "=" * 50)
    print("4. 🔄 MAC SPOOFING INDIVIDUAL (5 segundos)")
    print("=" * 50)
    spoof_attack = mac_spoofing(iface, "12:34:56:78:9a:bc", verbose=True)
    if spoof_attack:
        sleep(5)
        spoof_attack.restore_original_mac()

    print("\n" + "=" * 60)
    print("🎯 DEMO FINALIZADA - RESUMEN")
    print("=" * 60)
    print("✅ MAC Flooding - FUNCIONA SIEMPRE")
    print("✅ MAC Duplication - FUNCIONA SIEMPRE")
    print("🔄 Vendor MAC - DEPENDE DE PERMISOS")
    print("🔄 MAC Spoofing - DEPENDE DE PERMISOS")

    if system == 'Darwin':
        print("\n💡 PARA SPOOFING REAL EN macOS:")
        print("   1. Reinicia en Recovery Mode (Cmd+R)")
        print("   2. Ejecuta: csrutil disable")
        print("   3. Reinicia y ejecuta con sudo")


if __name__ == "__main__":
    system = platform.system()
    iface = "en0" if system == 'Darwin' else "eth0"

    # Verificar permisos
    if system == 'Darwin' and os.geteuid() != 0:
        print("⚠️  Ejecuta con sudo para mejores resultados en macOS")
        print("   Ejemplo: sudo python3 mac_advanced.py")

    demo_macos_enhanced(iface)
    iface = "en0" if system == 'Darwin' else "eth0"

    # Verificar permisos
    if system == 'Darwin' and os.geteuid() != 0:
        print("⚠️  Ejecuta con sudo para mejores resultados en macOS")
        print("   Ejemplo: sudo python3 mac_advanced.py")

    demo_macos_enhanced(iface)