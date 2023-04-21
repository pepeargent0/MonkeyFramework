import pytest
from subprocess import run, PIPE
from attack.leyer_2.mac import mac_spoofing
from utils.interface import create_virtual_interface, delete_virtual_interface


def test_valid_mac():
    iface = "test1-2"
    create_virtual_interface(iface)
    mac = "00:11:22:33:44:55"
    mac_spoofing(iface, mac)
    result = run(['ifconfig', iface], stdout=PIPE, stderr=PIPE)
    assert mac in result.stdout.decode()
    delete_virtual_interface(iface)


def test_invalid_iface():
    iface = "invalid_iface"
    mac = "00:11:22:33:44:55"
    with pytest.raises(Exception):
        mac_spoofing(iface, mac)


def test_invalid_mac():
    iface = "test-2"
    create_virtual_interface(iface)
    mac = "invalid_mac_address"
    with pytest.raises(Exception):
        mac_spoofing(iface, mac)
    delete_virtual_interface(iface)
