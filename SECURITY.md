# Security policy

Zupt handles cryptographic key material and is intended to protect data against capable adversaries. Vulnerabilities are taken seriously.

## Reporting a vulnerability

**Please do NOT open public GitHub issues for security vulnerabilities.**

Instead, email **cristian@securityops.co** with subject prefix `[SECURITY]`. PGP encrypted reports are preferred — fingerprint and public key available at https://wiki.securityops.co/pgp.

Include in your report:
- Affected version(s)
- Vulnerability class (cryptographic flaw, memory safety, side channel, supply chain, etc.)
- Reproduction steps or proof-of-concept code
- Impact assessment (what an attacker can achieve)
- Suggested mitigation if you have one

## What to expect

| Stage | Timeline |
|---|---|
| Acknowledgement | within 72 hours |
| Initial assessment | within 7 days |
| Fix in main branch | depends on severity |
| Public disclosure | coordinated with reporter, typically 30-90 days |

For critical vulnerabilities affecting confidentiality of data already encrypted with Zupt (e.g., a key recovery attack), an emergency release will be cut and the disclosure window may be shortened.

## Scope

In scope:
- Cryptographic implementation (KEM, AEAD, KDF, key derivation, randomness)
- Archive format parser (memory safety, denial-of-service)
- Key handling (memory wiping, format encoding/decoding)
- Storage Access Framework integration (write integrity, scratch file leakage)
- Dependency supply chain (BouncyCastle, Compose, etc.)

Out of scope:
- Vulnerabilities in Android OS or kernel
- Hardware-level side channels (cache timing, EM emanation, fault injection)
- Physical attacks on a device the user no longer controls
- Social engineering or coercion of a user holding keys
- Bugs in F-Droid or Google Play distribution channels

## Hall of fame

Reporters who responsibly disclose vulnerabilities will be credited in the release notes (with consent).

## Cryptographic primitives

The cryptography Zupt depends on:

- **ML-KEM-768** (NIST FIPS 203) — implemented in BouncyCastle
- **X25519** (RFC 7748) — implemented in BouncyCastle
- **AES-256-GCM** (NIST SP 800-38D) — implemented in BouncyCastle (with hardware acceleration where available)
- **PBKDF2-HMAC-SHA512** (RFC 8018) — implemented in BouncyCastle
- **SHAKE256** (NIST FIPS 202) — implemented in BouncyCastle

We trust these primitives' published security analyses. If a primitive is found broken (e.g., an ML-KEM-768 attack reduces it below 192-bit security), we will:
1. Issue a security advisory immediately
2. Release an updated app with a replacement primitive (e.g., HQC if ML-KEM falls)
3. Document migration steps for users to re-encrypt existing archives

The hybrid PQ + classical construction (ML-KEM + X25519) means breaking *one* primitive does not compromise archives — the attacker would need to break both ML-KEM and X25519.
