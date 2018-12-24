
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

    class TestPoly1305(unittest.TestCase):

        def test_poly1305_mac(self):
            msg = b'Cryptographic Forum Research Group'
            key = binascii.unhexlify(
                b'85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b')
            tag = poly1305_mac(msg, key)

            expected_tag = binascii.unhexlify(b'a8061dc1305136c6c22b8baf0c0127a9')

            self.assertEqual(tag, expected_tag)

        def test_poly1305_mac_appendixA_3_1(self):
            msg = binascii.unhexlify(b'00000000000000000000000000000000' * 4)
            key = binascii.unhexlify(b'00000000000000000000000000000000' * 2)
            tag = poly1305_mac(msg, key)

            expected_tag = binascii.unhexlify(b'00000000000000000000000000000000')

            self.assertEqual(tag, expected_tag)

        def test_poly1305_mac_appendixA_3_2(self):
            msg = b'Any submission to the IETF intended by the Contributor for publication as all or part of an IETF Internet-Draft or RFC and any statement made within the context of an IETF activity is considered an "IETF Contribution". Such statements include oral statements in IETF sessions, as well as written and electronic communications made at any time or place, which are addressed to'
            key = binascii.unhexlify(
                b'0000000000000000000000000000000036e5f6b5c5e06070f0efca96227a863e')
            tag = poly1305_mac(msg, key)

            expected_tag = binascii.unhexlify(b'36e5f6b5c5e06070f0efca96227a863e')

            self.assertEqual(tag, expected_tag)

        def test_poly1305_mac_appendixA_3_3(self):
            msg = b'Any submission to the IETF intended by the Contributor for publication as all or part of an IETF Internet-Draft or RFC and any statement made within the context of an IETF activity is considered an "IETF Contribution". Such statements include oral statements in IETF sessions, as well as written and electronic communications made at any time or place, which are addressed to'
            key = binascii.unhexlify(
                b'36e5f6b5c5e06070f0efca96227a863e00000000000000000000000000000000')
            tag = poly1305_mac(msg, key)

            expected_tag = binascii.unhexlify(b'f3477e7cd95417af89a6b8794c310cf0')

            self.assertEqual(tag, expected_tag)

        def test_poly1305_mac_appendixA_3_4(self):
            msg = binascii.unhexlify(b''.join(b'''
                27 54 77 61 73 20 62 72 69 6c 6c 69 67 2c 20 61
                6e 64 20 74 68 65 20 73 6c 69 74 68 79 20 74 6f
                76 65 73 0a 44 69 64 20 67 79 72 65 20 61 6e 64
                20 67 69 6d 62 6c 65 20 69 6e 20 74 68 65 20 77
                61 62 65 3a 0a 41 6c 6c 20 6d 69 6d 73 79 20 77
                65 72 65 20 74 68 65 20 62 6f 72 6f 67 6f 76 65
                73 2c 0a 41 6e 64 20 74 68 65 20 6d 6f 6d 65 20
                72 61 74 68 73 20 6f 75 74 67 72 61 62 65 2e
            '''.split()))
            key = binascii.unhexlify(
                b'1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0')
            tag = poly1305_mac(msg, key)

            expected_tag = binascii.unhexlify(b'4541669a7eaaee61e708dc7cbcc5eb62')

            self.assertEqual(tag, expected_tag)

        def test_poly1305_mac_appendixA_3_5(self):
            # If one uses 130-bit partial reduction, does the code
            # handle the case where partially reduced final result is not fully
            # reduced?
            msg = binascii.unhexlify(
                b'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF')
            key = binascii.unhexlify(
                b'0200000000000000000000000000000000000000000000000000000000000000')
            tag = poly1305_mac(msg, key)

            expected_tag = binascii.unhexlify(b'03000000000000000000000000000000')

            self.assertEqual(tag, expected_tag)

        def test_poly1305_mac_appendixA_3_6(self):
            # What happens if addition of s overflows modulo 2^128?
            msg = binascii.unhexlify(
                b'02000000000000000000000000000000')
            key = binascii.unhexlify(
                b'02000000000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF')
            tag = poly1305_mac(msg, key)

            expected_tag = binascii.unhexlify(b'03000000000000000000000000000000')

            self.assertEqual(tag, expected_tag)

        def test_poly1305_mac_appendixA_3_7(self):
            # What happens if data limb is all ones and there is
            # carry from lower limb?
            msg = binascii.unhexlify(b''.join(b'''
                FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
                F0 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
                11 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            '''.split()))
            key = binascii.unhexlify(
                b'0100000000000000000000000000000000000000000000000000000000000000')
            tag = poly1305_mac(msg, key)

            expected_tag = binascii.unhexlify(b'05000000000000000000000000000000')

            self.assertEqual(tag, expected_tag)

        def test_poly1305_mac_appendixA_3_8(self):
            # What happens if final result from polynomial part is
            # exactly 2^130-5?
            msg = binascii.unhexlify(b''.join(b'''
                FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
                FB FE FE FE FE FE FE FE FE FE FE FE FE FE FE FE
                01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01
            '''.split()))
            key = binascii.unhexlify(
                b'0100000000000000000000000000000000000000000000000000000000000000')
            tag = poly1305_mac(msg, key)

            expected_tag = binascii.unhexlify(b'00000000000000000000000000000000')

            self.assertEqual(tag, expected_tag)

        def test_poly1305_mac_appendixA_3_9(self):
            # What happens if final result from polynomial part is
            # exactly 2^130-6?
            msg = binascii.unhexlify(b''.join(b'''
                FD FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
            '''.split()))
            key = binascii.unhexlify(
                b'0200000000000000000000000000000000000000000000000000000000000000')
            tag = poly1305_mac(msg, key)

            expected_tag = binascii.unhexlify(b'FAFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF')

            self.assertEqual(tag, expected_tag)

        def test_poly1305_mac_appendixA_3_10(self):
            # What happens if 5*H+L-type reduction produces
            # 131-bit intermediate result?
            msg = binascii.unhexlify(b''.join(b'''
                E3 35 94 D7 50 5E 43 B9 00 00 00 00 00 00 00 00
                33 94 D7 50 5E 43 79 CD 01 00 00 00 00 00 00 00
                00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            '''.split()))
            key = binascii.unhexlify(
                b'0100000000000000040000000000000000000000000000000000000000000000')
            tag = poly1305_mac(msg, key)

            expected_tag = binascii.unhexlify(b'14000000000000005500000000000000')

            self.assertEqual(tag, expected_tag)

        def test_poly1305_mac_appendixA_3_11(self):
            # What happens if 5*H+L-type reduction produces
            # 131-bit final result?
            msg = binascii.unhexlify(b''.join(b'''
                E3 35 94 D7 50 5E 43 B9 00 00 00 00 00 00 00 00
                33 94 D7 50 5E 43 79 CD 01 00 00 00 00 00 00 00
                00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            '''.split()))
            key = binascii.unhexlify(
                b'0100000000000000040000000000000000000000000000000000000000000000')
            tag = poly1305_mac(msg, key)

            expected_tag = binascii.unhexlify(b'13000000000000000000000000000000')

            self.assertEqual(tag, expected_tag)


    unittest.main()
