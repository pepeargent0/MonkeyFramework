from subprocess import check_call


def create_virtual_interface(iface_name: str) -> None:
    #check_call(['ip', 'link', 'add', 'dev', iface_name, 'type', 'dummy','addr', ''])
    #check_call(['ip', 'link', 'set', 'dev', iface_name, 'up'])
    #check_call(['ip', 'addr', 'add', '10.10.10.10/24', 'dev', iface_name])

    check_call(['iw', 'dev', iface_name, 'interface', 'add', iface_name, 'type', 'dummy', 'addr', '11:11:22:33:44:55'])
    check_call(['ifconfig', iface_name, 'up'])


def delete_virtual_interface(iface: str):
    check_call(['sudo', 'ip', 'link', 'delete', iface])
