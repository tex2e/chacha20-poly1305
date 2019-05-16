
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

def decrypt_and_verify(key, nonce, plaintext, mac, aad):
    plaintext, tag = \
        chacha20_aead_decrypt(key=key, nonce=nonce, plaintext=plaintext, aad=aad)

    if compare_const_time(tag, mac):
        return Exception('bad tag!')

    return plaintext


if __name__ == '__main__':
    import unittest

    class TestChacha20Poly1305(unittest.TestCase):

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

        def test_poly1305_key_gen_appendixA_4_1(self):
            key = binascii.unhexlify(
                b'0000000000000000000000000000000000000000000000000000000000000000')
            nonce = binascii.unhexlify(b'000000000000000000000000')
            onetime_key = poly1305_key_gen(key, nonce)

            expected_bytes = binascii.unhexlify(b''.join(b'''
                76 b8 e0 ad a0 f1 3d 90 40 5d 6a e5 53 86 bd 28
                bd d2 19 b8 a0 8d ed 1a a8 36 ef cc 8b 77 0d c7
            '''.split()))

            self.assertEqual(onetime_key, expected_bytes)

        def test_poly1305_key_gen_appendixA_4_2(self):
            key = binascii.unhexlify(
                b'0000000000000000000000000000000000000000000000000000000000000001')
            nonce = binascii.unhexlify(b'000000000000000000000002')
            onetime_key = poly1305_key_gen(key, nonce)

            expected_bytes = binascii.unhexlify(b''.join(b'''
                ec fa 25 4f 84 5f 64 74 73 d3 cb 14 0d a9 e8 76
                06 cb 33 06 6c 44 7b 87 bc 26 66 dd e3 fb b7 39
            '''.split()))

            self.assertEqual(onetime_key, expected_bytes)

        def test_poly1305_key_gen_appendixA_4_3(self):
            key = binascii.unhexlify(
                b'1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0')
            nonce = binascii.unhexlify(b'000000000000000000000002')
            onetime_key = poly1305_key_gen(key, nonce)

            expected_bytes = binascii.unhexlify(b''.join(b'''
                96 5e 3b c6 f9 ec 7e d9 56 08 08 f4 d2 29 f9 4b
                13 7f f2 75 ca 9b 3f cb dd 59 de aa d2 33 10 ae
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
            nonce = constant + iv
            ciphertext, tag = chacha20_aead_encrypt(aad, key, nonce, plaintext)

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

        def test_chacha20poly1305_aead_decryption_appendixA_5_1(self):
            aad = binascii.unhexlify(b'f33388860000000000004e91')
            key = binascii.unhexlify(b''.join(b'''
                1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0
                47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0
            '''.split()))
            nonce = binascii.unhexlify(b'000000000102030405060708')
            ciphertext = binascii.unhexlify(b''.join(b'''
                64 a0 86 15 75 86 1a f4 60 f0 62 c7 9b e6 43 bd
                5e 80 5c fd 34 5c f3 89 f1 08 67 0a c7 6c 8c b2
                4c 6c fc 18 75 5d 43 ee a0 9e e9 4e 38 2d 26 b0
                bd b7 b7 3c 32 1b 01 00 d4 f0 3b 7f 35 58 94 cf
                33 2f 83 0e 71 0b 97 ce 98 c8 a8 4a bd 0b 94 81
                14 ad 17 6e 00 8d 33 bd 60 f9 82 b1 ff 37 c8 55
                97 97 a0 6e f4 f0 ef 61 c1 86 32 4e 2b 35 06 38
                36 06 90 7b 6a 7c 02 b0 f9 f6 15 7b 53 c8 67 e4
                b9 16 6c 76 7b 80 4d 46 a5 9b 52 16 cd e7 a4 e9
                90 40 c5 a4 04 33 22 5e e2 82 a1 b0 a0 6c 52 3e
                af 45 34 d7 f8 3f a1 15 5b 00 47 71 8c bc 54 6a
                0d 07 2b 04 b3 56 4e ea 1b 42 22 73 f5 48 27 1a
                0b b2 31 60 53 fa 76 99 19 55 eb d6 31 59 43 4e
                ce bb 4e 46 6d ae 5a 10 73 a6 72 76 27 09 7a 10
                49 e6 17 d9 1d 36 10 94 fa 68 f0 ff 77 98 71 30
                30 5b ea ba 2e da 04 df 99 7b 71 4d 6c 6f 2c 29
                a6 ad 5c b4 02 2b 02 70 9b
            '''.split()))

            plaintext, tag = chacha20_aead_decrypt(aad, key, nonce, ciphertext)

            expected_plaintext = binascii.unhexlify(b''.join(b'''
                49 6e 74 65 72 6e 65 74 2d 44 72 61 66 74 73 20
                61 72 65 20 64 72 61 66 74 20 64 6f 63 75 6d 65
                6e 74 73 20 76 61 6c 69 64 20 66 6f 72 20 61 20
                6d 61 78 69 6d 75 6d 20 6f 66 20 73 69 78 20 6d
                6f 6e 74 68 73 20 61 6e 64 20 6d 61 79 20 62 65
                20 75 70 64 61 74 65 64 2c 20 72 65 70 6c 61 63
                65 64 2c 20 6f 72 20 6f 62 73 6f 6c 65 74 65 64
                20 62 79 20 6f 74 68 65 72 20 64 6f 63 75 6d 65
                6e 74 73 20 61 74 20 61 6e 79 20 74 69 6d 65 2e
                20 49 74 20 69 73 20 69 6e 61 70 70 72 6f 70 72
                69 61 74 65 20 74 6f 20 75 73 65 20 49 6e 74 65
                72 6e 65 74 2d 44 72 61 66 74 73 20 61 73 20 72
                65 66 65 72 65 6e 63 65 20 6d 61 74 65 72 69 61
                6c 20 6f 72 20 74 6f 20 63 69 74 65 20 74 68 65
                6d 20 6f 74 68 65 72 20 74 68 61 6e 20 61 73 20
                2f e2 80 9c 77 6f 72 6b 20 69 6e 20 70 72 6f 67
                72 65 73 73 2e 2f e2 80 9d
            '''.split()))
            expected_tag = binascii.unhexlify(b'eead9d67890cbb22392336fea1851f38')

            self.assertEqual(plaintext, expected_plaintext)
            self.assertEqual(tag, expected_tag)


    unittest.main()
