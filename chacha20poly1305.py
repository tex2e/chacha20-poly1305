
import binascii
from chacha20 import chacha20_block
from utils.hexdump import hexdump

def poly1305_key_gen(key: bytes, nonce: bytes):
    counter = 0
    block = chacha20_block(key, counter, nonce)
    return block[0:32]



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

    unittest.main()
