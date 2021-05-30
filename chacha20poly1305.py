import struct
import binascii
from chacha20 import chacha20_block, chacha20_encrypt
from poly1305 import poly1305_mac
from utils.hexdump import hexdump

def poly1305_key_gen(key: bytes, nonce: bytes) -> bytes:
    counter = 0
    block = chacha20_block(key, counter, nonce)
    return block[0:32]

def pad16(x: bytes) -> bytes:
    if len(x) % 16 == 0: return b''
    return b'\x00' * (16 - (len(x) % 16))

def num_to_8_le_bytes(num: int) -> bytes:
    return struct.pack('<Q', num)

def chacha20_aead_encrypt(aad: bytes, key: bytes, nonce: bytes, plaintext: bytes):
    otk = poly1305_key_gen(key, nonce)
    ciphertext = chacha20_encrypt(key, 1, nonce, plaintext)
    mac_data = aad + pad16(aad)
    mac_data += ciphertext + pad16(ciphertext)
    mac_data += num_to_8_le_bytes(len(aad))
    mac_data += num_to_8_le_bytes(len(ciphertext))
    tag = poly1305_mac(mac_data, otk)
    return (ciphertext, tag)

def chacha20_aead_decrypt(aad: bytes, key: bytes, nonce: bytes, ciphertext: bytes):
    otk = poly1305_key_gen(key, nonce)
    plaintext = chacha20_encrypt(key, 1, nonce, ciphertext)
    mac_data = aad + pad16(aad)
    mac_data += ciphertext + pad16(ciphertext)
    mac_data += num_to_8_le_bytes(len(aad))
    mac_data += num_to_8_le_bytes(len(ciphertext))
    tag = poly1305_mac(mac_data, otk)
    return (plaintext, tag)


def compare_const_time(a, b):
    """Compare strings in constant time."""
    if len(a) != len(b): return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0

def encrypt_and_tag(key, nonce, plaintext, aad):
    return chacha20_aead_encrypt(key=key, nonce=nonce, plaintext=plaintext, aad=aad)

def decrypt_and_verify(key, nonce, ciphertext, mac, aad):
    plaintext, tag = \
        chacha20_aead_decrypt(key=key, nonce=nonce, ciphertext=ciphertext, aad=aad)

    if not compare_const_time(tag, mac):
        return Exception('bad tag!')

    return plaintext
