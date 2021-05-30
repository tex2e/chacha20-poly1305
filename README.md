
[![Chacha20Poly1305](https://circleci.com/gh/tex2e/chacha20-poly1305.svg?style=shield)](https://circleci.com/gh/tex2e/chacha20-poly1305)


# ChaCha20 and Poly1305 for IETF Protocols (RFC 8439)

This provides three algorithms:

1. The ChaCha20 cipher.
2. The Poly1305 authenticator.
3. The CHACHA20-POLY1305 Authenticated Encryption with Associated
    Data (AEAD) construction.

## Unit Tests

```bash
python -m unittest discover tests
```

## References

- [ChaCha20 and Poly1305 for IETF Protocols (RFC 8439)](https://tools.ietf.org/html/rfc8439)
- [ChaCha20 and Poly1305 for IETF Protocols (RFC 7539) -- Obsoleted](https://tools.ietf.org/html/rfc7539)
- [ChaCha, a variant of Salsa20](http://cr.yp.to/chacha/chacha-20080128.pdf)
- [The Poly1305-AES message-authentication code](http://cr.yp.to/mac/poly1305-20050329.pdf)
- [An Interface and Algorithms for Authenticated Encryption (RFC 5116)](https://tools.ietf.org/html/rfc5116)
  - [3.2. Recommended Nonce Formation](https://tools.ietf.org/html/rfc5116#section-3.2)
  - [4. Requirements on AEAD Algorithm Specifications](https://tools.ietf.org/html/rfc5116#section-4)

---

- [Cache-Collision Timing Attacks Against AES](https://www.microsoft.com/en-us/research/wp-content/uploads/2006/10/aes-timing.pdf)
- [Advanced Encryption Standard (AES)](https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf)
- [New Features of Latin Dances: Analysis of Salsa, ChaCha, and Rumba](http://cr.yp.to/rumba20/newfeatures-20071218.pdf)
- [Modified version of 'Latin Dances Revisited: New Analytic Results of Salsa20 and ChaCha'](https://eprint.iacr.org/2012/065.pdf)
- [NaCl: Networking and Cryptography library](http://nacl.cr.yp.to/)
- [poly1305-donna (GitHub)](https://github.com/floodyberry/poly1305-donna)
- [A Security Analysis of the Composition of ChaCha20 and Poly1305](https://eprint.iacr.org/2014/613.pdf)
- [Recommendation for the Triple Data Encryption Algorithm (TDEA) Block Cipher (NIST 800-67)](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-67r2.pdf)
- [Selection of Future Cryptographic Standards](https://tools.ietf.org/html/draft-mcgrew-standby-cipher-00)
- [Performance Measurements of ChaCha20](https://www.imperialviolet.org/2014/02/27/tlssymmetriccrypto.html)
