from random import randint


def generate_mac_random() -> str:
    mac_bytes = [randint(0x00, 0xff) for _ in range(6)]
    mac_bytes[0] &= 0xfe
    mac_address = ":".join(["{:02x}".format(b) for b in mac_bytes])
    return mac_address
