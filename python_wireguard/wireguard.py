'''
This file contains functions for directly interacting with the Wireguard shared objects file.
'''
# pylint: disable-next=too-many-arguments
# pylint: disable-next=too-many-positional-arguments

from ctypes import CDLL, c_ushort, create_string_buffer
import re
import os

dirname = os.path.dirname(os.path.realpath(__file__))
c_library = CDLL(dirname + '/bin/py-wireguard.so')

def valid_interface(interface):
    '''
    Validate the name of a network interface.
    '''
    return bool(re.match("^[A-Za-z0-9_-]*$", interface))

def empty_key():
    '''
    Create an empty key. Used for generating new keys, you should not need this.
    '''
    return create_string_buffer(b'\000' * 32)

def key_pair():
    '''
    Create a private/public key pair fo ruse with Wireguard.
    '''
    private, public = empty_key(), empty_key()
    c_library.generate_private_key(private)
    c_library.generate_public_key(private, public)
    return private, public

def key_pubkey(private):
    '''
    Return a public key from a private key
    '''
    public=empty_key()
    c_library.generate_public_key(key_from_base64(private), public)
    return key_to_base64(public)

def create_server(name, port, private_key, local_ip):
    '''
    Create a server-side Wireguard interface. This is a Wireguard instance that listens on a port
    to allow clients to connect.
    '''
    if valid_interface(name):
        c_library.add_server_device(name.encode(), c_ushort(port), private_key)
        os.system(f"ip a add dev {name} {local_ip}")
    else:
        print(f"invalid device name '{name}'")

def create_client(name, private_key, local_ip):
    '''
    Create a client-side Wireguard interface. This means that it won't be listening on a port.
    '''
    if valid_interface(name):
        c_library.add_client_device(name.encode(), private_key)
        os.system(f"ip a add dev {name} {local_ip}")
    else:
        print(f"invalid device name '{name}'")

def client_add_peer(device_name, public_key, address, port):
    '''
    Add a 'peer' to a client-side setup. This means that the server will be added for this setup.
    '''
    c_library.add_server_peer(device_name.encode(), public_key, address.encode(), c_ushort(port))

def server_add_peer(device_name, public_key, local_ip):
    '''
    Add a client
    '''
    c_library.add_client_peer(device_name.encode(), public_key, local_ip.encode())

def add_peer_endpoint(device_name,
                      public_key,
                      preshared_key,
                      allowed_ip_address,
                      allowed_ip_address_cidr,
                      peer_ip_address,
                      ip_address, port,
                      persistent_keepalive):
    '''
    Add a peer to device 'device_name'.
    '''

    if preshared_key:
        psk=key_from_base64(preshared_key)
    else:
        psk=None

    if public_key:
        pubk=key_from_base64(public_key)
    else:
        pubk=None

    c_library.add_peer_endpoint(
        device_name.encode(),
        pubk,
        psk,
        allowed_ip_address.encode(),
        int(allowed_ip_address_cidr),
        peer_ip_address.encode(),
        ip_address.encode(),
        int(port),
        int(persistent_keepalive))

def delete_device(name):
    '''
    Delete interface :name:
    '''
    c_library.delete_device(name.encode())

def list_devices():
    '''
    Print a list of all Wireguard network devices.
    '''

    c_library.list_devices()

def get_devices(max_size=10000):
    '''
    get a list of  all Wireguard network devices.
    '''
    if max_size<2:
        return "",-1
    res = create_string_buffer(max_size)
    returncode = c_library.get_devices(res,max_size)
    return res.value.decode(),returncode

def key_to_base64(key):
    '''
    Convert a binary key to base64.
    '''
    str_val = create_string_buffer(b'\000' * 44)
    c_library.key_to_string(key, str_val)
    return str_val.value.decode()

def key_from_base64(base64):
    '''
    Create a binary key from a base64 string.
    '''
    key = empty_key()
    c_library.key_from_string(base64.encode(), key)
    return key

def enable_device(device):
    '''
    Turn on a network device with name :device:.
    '''
    if valid_interface(device):
        os.system(f"ip link set up {device}")
    else:
        print(f"invalid device '{device}'")
