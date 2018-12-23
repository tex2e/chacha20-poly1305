
# https://tools.ietf.org/html/rfc8439

import struct
import binascii
from typing import List

# Finite field 2^32
class F2_32:
    def __init__(self, val: int):
        assert isinstance(val, int)
        self.val = val
    def __add__(self, other):
        return F2_32((self.val + other.val) & 0xffffffff)
    def __xor__(self, other):
        return F2_32(self.val ^ other.val)
    def __lshift__(self, nbit: int):
        left  = (self.val << nbit%32) & 0xffffffff
        right = (self.val & 0xffffffff) >> (32-(nbit%32))
        return F2_32(left | right)
    def __repr__(self):
        return hex(self.val)
    def __int__(self):
        return int(self.val)

def quarter_round(a: F2_32, b: F2_32, c: F2_32, d: F2_32):
    a += b; d ^= a; d <<= 16;
    c += d; b ^= c; b <<= 12;
    a += b; d ^= a; d <<= 8;
    c += d; b ^= c; b <<= 7;
    return a, b, c, d

def Qround(state: List[F2_32], idx1, idx2, idx3, idx4):
    state[idx1], state[idx2], state[idx3], state[idx4] = \
        quarter_round(state[idx1], state[idx2], state[idx3], state[idx4])

def inner_block(state: List[F2_32]):
    Qround(state, 0, 4, 8, 12)
    Qround(state, 1, 5, 9, 13)
    Qround(state, 2, 6, 10, 14)
    Qround(state, 3, 7, 11, 15)
    Qround(state, 0, 5, 10, 15)
    Qround(state, 1, 6, 11, 12)
    Qround(state, 2, 7, 8, 13)
    Qround(state, 3, 4, 9, 14)
    return state

def chacha20_block(key: bytes, counter: int, nonce: bytes) -> List[bytes]:
    # make a state matrix
    constants = [F2_32(x) for x in struct.unpack('<IIII', b'expand 32-byte k')]
    key       = [F2_32(x) for x in struct.unpack('<IIIIIIII', key)]
    counter   = [F2_32(counter)]
    nonce     = [F2_32(x) for x in struct.unpack('<III', nonce)]
    state = constants + key + counter + nonce
    initial_state = state[:]
    for i in range(1, 11):
        state = inner_block(state)
    state = [ s + init_s for s, init_s in zip(state, initial_state) ]
    return serialize(state)

def serialize(state: List[F2_32]) -> List[bytes]:
    return [ struct.pack('<I', int(s)) for s in state ]



if __name__ == '__main__':
    import unittest

    class TestChacha20(unittest.TestCase):

        def test_quarter_round(self):
            a = F2_32(0x11111111)
            b = F2_32(0x01020304)
            c = F2_32(0x9b8d6f43)
            d = F2_32(0x01234567)
            a, b, c, d = quarter_round(a, b, c, d)
            self.assertEqual(int(a), 0xea2a92f4)
            self.assertEqual(int(b), 0xcb1cf8ce)
            self.assertEqual(int(c), 0x4581472e)
            self.assertEqual(int(d), 0x5881c4bb)

        def test_chacha20_block(self):
            key = binascii.unhexlify(
                b'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')
            counter = 0x00000001
            nonce = binascii.unhexlify(
                b'000000090000004a00000000')
            state = chacha20_block(key, counter, nonce)

            state_bytes = bytearray(0)
            for s in state:
                state_bytes += s

            expected_bytes = binascii.unhexlify(b''.join(b'''
                10 f1 e7 e4 d1 3b 59 15 50 0f dd 1f a3 20 71 c4
                c7 d1 f4 c7 33 c0 68 03 04 22 aa 9a c3 d4 6c 4e
                d2 82 64 46 07 9f aa 09 14 c2 d7 05 d9 8b 02 a2
                b5 12 9c d1 de 16 4e b9 cb d0 83 e8 a2 50 3c 4e
            '''.split()))

            self.assertEqual(state_bytes, expected_bytes)


    unittest.main()
