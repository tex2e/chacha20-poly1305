
import math
import binascii

def clamp(r: int) -> int:
    return r & 0x0ffffffc0ffffffc0ffffffc0fffffff

def le_bytes_to_num(byte) -> int:
    res = 0
    for i in range(len(byte) - 1, -1, -1):
        res <<= 8
        res += byte[i]
    return res

def num_to_16_le_bytes(num: int) -> bytes:
    res = []
    for i in range(16):
        res.append(num & 0xff)
        num >>= 8
    return bytearray(res)

def poly1305_mac(msg: bytes, key: bytes) -> bytes:
    r = le_bytes_to_num(key[0:16])
    r = clamp(r)
    s = le_bytes_to_num(key[16:32])
    a = 0  # a is the accumulator
    p = (1<<130) - 5
    for i in range(1, math.ceil(len(msg)/16) + 1):
        n = le_bytes_to_num(msg[(i-1)*16 : i*16] + b'\x01')
        a += n
        a = (r * a) % p
    a += s
    return num_to_16_le_bytes(a)



if __name__ == '__main__':
    import unittest

    class TestChacha20(unittest.TestCase):

        def test_poly1305_mac(self):
            msg = b'Cryptographic Forum Research Group'
            key = binascii.unhexlify(
                b'85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b')
            tag = poly1305_mac(msg, key)

            expected_bytes = binascii.unhexlify(b'a8061dc1305136c6c22b8baf0c0127a9')

            self.assertEqual(tag, expected_bytes)

    unittest.main()
