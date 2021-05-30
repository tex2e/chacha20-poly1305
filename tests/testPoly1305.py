import unittest
from poly1305 import *

class TestPoly1305(unittest.TestCase):

    def test_poly1305_mac(self):
        msg = b'Cryptographic Forum Research Group'
        key = bytes.fromhex(
            '85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b')
        tag = poly1305_mac(msg, key)

        expected_tag = bytes.fromhex('a8061dc1305136c6c22b8baf0c0127a9')

        self.assertEqual(tag, expected_tag)

    def test_poly1305_mac_appendixA_3_1(self):
        msg = bytes.fromhex('00000000000000000000000000000000' * 4)
        key = bytes.fromhex('00000000000000000000000000000000' * 2)
        tag = poly1305_mac(msg, key)

        expected_tag = bytes.fromhex('00000000000000000000000000000000')

        self.assertEqual(tag, expected_tag)

    def test_poly1305_mac_appendixA_3_2(self):
        msg = b'Any submission to the IETF intended by the Contributor for publication as all or part of an IETF Internet-Draft or RFC and any statement made within the context of an IETF activity is considered an "IETF Contribution". Such statements include oral statements in IETF sessions, as well as written and electronic communications made at any time or place, which are addressed to'
        key = bytes.fromhex(
            '0000000000000000000000000000000036e5f6b5c5e06070f0efca96227a863e')
        tag = poly1305_mac(msg, key)

        expected_tag = bytes.fromhex('36e5f6b5c5e06070f0efca96227a863e')

        self.assertEqual(tag, expected_tag)

    def test_poly1305_mac_appendixA_3_3(self):
        msg = b'Any submission to the IETF intended by the Contributor for publication as all or part of an IETF Internet-Draft or RFC and any statement made within the context of an IETF activity is considered an "IETF Contribution". Such statements include oral statements in IETF sessions, as well as written and electronic communications made at any time or place, which are addressed to'
        key = bytes.fromhex(
            '36e5f6b5c5e06070f0efca96227a863e00000000000000000000000000000000')
        tag = poly1305_mac(msg, key)

        expected_tag = bytes.fromhex('f3477e7cd95417af89a6b8794c310cf0')

        self.assertEqual(tag, expected_tag)

    def test_poly1305_mac_appendixA_3_4(self):
        msg = bytes.fromhex('''
            27 54 77 61 73 20 62 72 69 6c 6c 69 67 2c 20 61
            6e 64 20 74 68 65 20 73 6c 69 74 68 79 20 74 6f
            76 65 73 0a 44 69 64 20 67 79 72 65 20 61 6e 64
            20 67 69 6d 62 6c 65 20 69 6e 20 74 68 65 20 77
            61 62 65 3a 0a 41 6c 6c 20 6d 69 6d 73 79 20 77
            65 72 65 20 74 68 65 20 62 6f 72 6f 67 6f 76 65
            73 2c 0a 41 6e 64 20 74 68 65 20 6d 6f 6d 65 20
            72 61 74 68 73 20 6f 75 74 67 72 61 62 65 2e
        ''')
        key = bytes.fromhex(
            '1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0')
        tag = poly1305_mac(msg, key)

        expected_tag = bytes.fromhex('4541669a7eaaee61e708dc7cbcc5eb62')

        self.assertEqual(tag, expected_tag)

    def test_poly1305_mac_appendixA_3_5(self):
        # If one uses 130-bit partial reduction, does the code
        # handle the case where partially reduced final result is not fully
        # reduced?
        msg = bytes.fromhex(
            'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF')
        key = bytes.fromhex(
            '0200000000000000000000000000000000000000000000000000000000000000')
        tag = poly1305_mac(msg, key)

        expected_tag = bytes.fromhex('03000000000000000000000000000000')

        self.assertEqual(tag, expected_tag)

    def test_poly1305_mac_appendixA_3_6(self):
        # What happens if addition of s overflows modulo 2^128?
        msg = bytes.fromhex(
            '02000000000000000000000000000000')
        key = bytes.fromhex(
            '02000000000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF')
        tag = poly1305_mac(msg, key)

        expected_tag = bytes.fromhex('03000000000000000000000000000000')

        self.assertEqual(tag, expected_tag)

    def test_poly1305_mac_appendixA_3_7(self):
        # What happens if data limb is all ones and there is
        # carry from lower limb?
        msg = bytes.fromhex('''
            FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
            F0 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
            11 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        ''')
        key = bytes.fromhex(
            '0100000000000000000000000000000000000000000000000000000000000000')
        tag = poly1305_mac(msg, key)

        expected_tag = bytes.fromhex('05000000000000000000000000000000')

        self.assertEqual(tag, expected_tag)

    def test_poly1305_mac_appendixA_3_8(self):
        # What happens if final result from polynomial part is
        # exactly 2^130-5?
        msg = bytes.fromhex('''
            FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
            FB FE FE FE FE FE FE FE FE FE FE FE FE FE FE FE
            01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01
        ''')
        key = bytes.fromhex(
            '0100000000000000000000000000000000000000000000000000000000000000')
        tag = poly1305_mac(msg, key)

        expected_tag = bytes.fromhex('00000000000000000000000000000000')

        self.assertEqual(tag, expected_tag)

    def test_poly1305_mac_appendixA_3_9(self):
        # What happens if final result from polynomial part is
        # exactly 2^130-6?
        msg = bytes.fromhex('''
            FD FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
        ''')
        key = bytes.fromhex(
            '0200000000000000000000000000000000000000000000000000000000000000')
        tag = poly1305_mac(msg, key)

        expected_tag = bytes.fromhex('FAFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF')

        self.assertEqual(tag, expected_tag)

    def test_poly1305_mac_appendixA_3_10(self):
        # What happens if 5*H+L-type reduction produces
        # 131-bit intermediate result?
        msg = bytes.fromhex('''
            E3 35 94 D7 50 5E 43 B9 00 00 00 00 00 00 00 00
            33 94 D7 50 5E 43 79 CD 01 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        ''')
        key = bytes.fromhex(
            '0100000000000000040000000000000000000000000000000000000000000000')
        tag = poly1305_mac(msg, key)

        expected_tag = bytes.fromhex('14000000000000005500000000000000')

        self.assertEqual(tag, expected_tag)

    def test_poly1305_mac_appendixA_3_11(self):
        # What happens if 5*H+L-type reduction produces
        # 131-bit final result?
        msg = bytes.fromhex('''
            E3 35 94 D7 50 5E 43 B9 00 00 00 00 00 00 00 00
            33 94 D7 50 5E 43 79 CD 01 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        ''')
        key = bytes.fromhex(
            '0100000000000000040000000000000000000000000000000000000000000000')
        tag = poly1305_mac(msg, key)

        expected_tag = bytes.fromhex('13000000000000000000000000000000')

        self.assertEqual(tag, expected_tag)
