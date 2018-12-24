
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

def chacha20_aead_encrypt(aad: bytes, key: bytes, iv: bytes,
                          constant: bytes, plaintext: bytes):
    nonce = constant + iv
    otk = poly1305_key_gen(key, nonce)
    ciphertext = chacha20_encrypt(key, 1, nonce, plaintext)
    mac_data = aad + pad16(aad)
    mac_data += ciphertext + pad16(ciphertext)
    mac_data += num_to_8_le_bytes(len(aad))
    mac_data += num_to_8_le_bytes(len(ciphertext))
    tag = poly1305_mac(mac_data, otk)
    return (ciphertext, tag)



if __name__ == '__main__':
    import unittest

    class TestChacha20(unittest.TestCase):

        def test_poly1305_key_gen(self):
            key = binascii.unhexlify(
                b'808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f')
            nonce = binascii.unhexlify(b'000000000001020304050607')
            onetime_key = poly1305_key_gen(key, nonce)

            expected_bytes = binascii.unhexlify(b''.join(b'''
                8a d5 a0 8b 90 5f 81 cc 81 50 40 27 4a b2 94 71
                a8 33 b6 37 e3 fd 0d a5 08 db b8 e2 fd d1 a6 46
            '''.split()))

            self.assertEqual(onetime_key, expected_bytes)

        def test_chacha20_aead_encrypt(self):
            plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
            aad = binascii.unhexlify(b'50515253c0c1c2c3c4c5c6c7')
            key = binascii.unhexlify(b''.join(b'''
                80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f
                90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f
            '''.split()))
            iv = b'@ABCDEFG'
            constant = binascii.unhexlify(b'07000000')
            ciphertext, tag = chacha20_aead_encrypt(aad, key, iv, constant, plaintext)

            expected_ciphertext = binascii.unhexlify(b''.join(b'''
                d3 1a 8d 34 64 8e 60 db 7b 86 af bc 53 ef 7e c2
                a4 ad ed 51 29 6e 08 fe a9 e2 b5 a7 36 ee 62 d6
                3d be a4 5e 8c a9 67 12 82 fa fb 69 da 92 72 8b
                1a 71 de 0a 9e 06 0b 29 05 d6 a5 b6 7e cd 3b 36
                92 dd bd 7f 2d 77 8b 8c 98 03 ae e3 28 09 1b 58
                fa b3 24 e4 fa d6 75 94 55 85 80 8b 48 31 d7 bc
                3f f4 de f0 8e 4b 7a 9d e5 76 d2 65 86 ce c6 4b
                61 16
            '''.split()))
            expected_tag = binascii.unhexlify(b'1ae10b594f09e26a7e902ecbd0600691')

            self.assertEqual(ciphertext, expected_ciphertext)
            self.assertEqual(tag, expected_tag)

    unittest.main()
