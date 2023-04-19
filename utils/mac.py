from random import randint


def generate_mac_random() -> str:
    mac = bytearray([0x00, 0x16, 0x3e,
                     randint(0x00, 0x7f),
                     randint(0x00, 0xff),
                     randint(0x00, 0xff)])
    mac[0] |= 0x02  # set the "locally administered" bit
    return ':'.join(f"{x:02x}" for x in mac)

