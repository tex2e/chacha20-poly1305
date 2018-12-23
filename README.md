
# ChaCha20 and Poly1305 for IETF Protocols

This provides three algorithms:

1. The ChaCha20 cipher.
2. The Poly1305 authenticator.
3. The CHACHA20-POLY1305 Authenticated Encryption with Associated
    Data (AEAD) construction.


## The ChaCha Quarter Round

```
a += b; d ^= a; d <<<= 16;
c += d; b ^= c; b <<<= 12;
a += b; d ^= a; d <<<= 8;
c += d; b ^= c; b <<<= 7;
```

- `+` : integer addition modulo 2^32 : (a + b) & 0xffffffff
- `^` : bitwise XOR : a ^ b
- `<<< n` : n-bit left roll : (a << b) & 0xffffffff

## The ChaCha20 Block Function

The ChaCha20 state is initialized as follows:

-  The first four words (0-3) are constants: 0x61707865, 0x3320646e,
   0x79622d32, 0x6b206574.

-  The next eight words (4-11) are taken from the 256-bit key by
   reading the bytes in little-endian order, in 4-byte chunks.

-  Word 12 is a block counter.  Since each block is 64-byte, a 32-bit
   word is enough for 256 gigabytes of data.

-  Words 13-15 are a nonce, which MUST not be repeated for the same
   key.  The 13th word is the first 32 bits of the input nonce taken
   as a little-endian integer, while the 15th word is the last 32
   bits.

        cccccccc  cccccccc  cccccccc  cccccccc
        kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
        kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
        bbbbbbbb  nnnnnnnn  nnnnnnnn  nnnnnnnn

c=constant k=key b=blockcount n=nonce


## References

- [ChaCha20 and Poly1305 for IETF Protocols (RFC 8439)](https://tools.ietf.org/html/rfc8439)
- [ChaCha, a variant of Salsa20](http://cr.yp.to/chacha/chacha-20080128.pdf)
- [The Poly1305-AES message-authentication code](http://cr.yp.to/mac/poly1305-20050329.pdf)
- [Recommended Nonce Formation -- An Interface and Algorithms for Authenticated Encryption (RFC 5116)](https://tools.ietf.org/html/rfc5116#section-3.2)
