# Zupt for Android

> Post-quantum encrypted file compression. Fully offline. F-Droid ready.

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Android API](https://img.shields.io/badge/API-26%2B-brightgreen)](https://developer.android.com/about/versions/oreo)

Zupt is a privacy-first compression and encryption app for Android. It combines modern lossless compression (DEFLATE / Brotli / LZ4) with NIST-standardized post-quantum cryptography (ML-KEM-768) and authenticated symmetric encryption (AES-256-GCM). All processing happens on-device — no network code, no telemetry, no analytics, no ads.

Built for people who care about who can read their data, including five years from now when quantum computers can break ECDH but not ML-KEM.

---

## Why this exists

Cloud sync is convenient and dangerous. End-to-end encrypted services are better, but you still trust the provider's binary, the provider's auth flow, and the provider's continued existence. Zupt gives you a third option: encrypt locally with state-of-the-art cryptography, store the resulting `.zupt` file wherever you want — local SD card, USB-C drive, a Tor onion service, your friend's NAS — and decrypt only when you need the data back.

The post-quantum part matters. "Harvest now, decrypt later" is a real threat model: encrypted data captured today by a well-resourced adversary can be retroactively broken once Shor's algorithm becomes practical on cryptographically-relevant quantum hardware. Hybrid PQ + classical KEM (ML-KEM-768 + X25519, combined via SHAKE256) protects against this without sacrificing security if either primitive turns out to be broken.

---

## Features

- **Multi-file & folder compression** — pick any number of files, or a whole folder tree, into one `.zupt` archive
- **Streaming I/O** — memory is O(1 MiB) regardless of file size; compress files larger than your RAM
- **Hybrid post-quantum encryption** — ML-KEM-768 + X25519, secrets combined via SHAKE256
- **Authenticated symmetric encryption** — AES-256-GCM (FIPS 140-3 approved AEAD)
- **Strong KDF** — PBKDF2-HMAC-SHA512 at 1,000,000 iterations
- **Per-block + per-file integrity** — XXH64 on every 1 MiB block plus whole-file XXH64
- **Save verification** — every save is read back and byte-compared to detect storage providers that corrupt binary writes
- **Anti-forensics** — sensitive scratch files are zeroed on disk before deletion
- **No internet permission** — `INTERNET` is not declared in the manifest. The OS will refuse network calls
- **No broad storage permission** — uses only Storage Access Framework. Each operation explicitly asks the user
- **Encryption à la carte** — password, post-quantum, both, or neither

---

## Cryptographic specification

| Layer | Algorithm | Parameters |
|---|---|---|
| Key encapsulation (PQ) | ML-KEM-768 | NIST FIPS 203 |
| Key encapsulation (classical) | X25519 | RFC 7748 |
| Combiner | SHAKE256 | domain separator `"ZUPT-HYB-v1"` |
| AEAD | AES-256-GCM | 12-byte nonce, 16-byte tag |
| Password KDF | PBKDF2-HMAC-SHA512 | 1,000,000 iterations, 32-byte salt |
| Per-block integrity | XXH64 | non-cryptographic, fast |
| RNG | `SecureRandom.getInstanceStrong()` | with fallback |

For password+PQ archives, the password-derived key and hybrid KEM secret are combined via SHAKE256 with `"ZUPT-PWPQ-v1"`. Both must be supplied to decrypt — defence in depth against either being lost or compromised.

For wire format details, see [`SPEC.md`](SPEC.md).

---

## Installation

### F-Droid (recommended)

Coming soon. Package being prepared for inclusion in the official F-Droid repository.

### Direct APK

Download the latest signed APK from [Releases](https://github.com/cristiancmoises/zupt-android/releases). Verify the SHA-256 posted alongside the release before installing.

```bash
sha256sum zupt-vX.Y.Z.apk
adb install zupt-vX.Y.Z.apk
```

### Build from source

```bash
git clone https://github.com/cristiancmoises/zupt-android
cd zupt-android
./gradlew assembleRelease bundleRelease
```

Requires JDK 21, Android SDK 34 (build-tools 34.0.0). For production-signed builds, set environment variables `ZUPT_KEYSTORE`, `ZUPT_KS_PASS`, `ZUPT_KS_ALIAS`, `ZUPT_KS_KEY_PASS`.

The build is reproducible: same source tree + same toolchain → byte-identical APK across machines.

---

## Usage

### Compress

1. Open Zupt, tap **Compress**
2. Tap **Add files** to multi-select, or **Add folder** to recurse a directory tree
3. Choose codec (DEFLATE default; LZ4 for speed; Brotli for ratio)
4. Optionally set password and/or load post-quantum public key
5. Tap **Compress & Save**, pick destination

Memory stays at 4-8 MiB regardless of input size. A 5 GB folder backup uses the same RAM as a 5 KB document.

### Generate post-quantum keys

1. Tap **Keys** → **Generate keypair**
2. Save public key (share for encryption) and private key (keep secret) as `.key` files

### Extract

1. Tap **Extract**, pick a `.zupt`
2. App lists embedded files
3. Provide password and/or load private key
4. Tap **Extract**, pick destination folder

Multi-file archives recreate their directory structure inside the destination.

### Verify

The **Verify** screen runs the full extraction pipeline against a discarding sink. Checks GCM auth tag, every per-block XXH64, whole-file XXH64. Use to test long-stored archives.

---

## Architecture

- **`core.crypto`** — `Aead` (GCM), `Kdf` (PBKDF2), `HybridKem` (ML-KEM + X25519), `Xxh64`. No Android dependencies.
- **`core.codec`** — DEFLATE / Brotli / LZ4 behind common interface
- **`core.archive`** — wire format: `Format`, `Reader` (legacy in-memory), `Streaming` (production any-size I/O)
- **`core.io`** — `SafFiles` wraps SAF with binary-safe writes and read-back verification
- **`ui`** — Compose Material 3 screens

No service, no background work, no broadcast receiver, no content provider. Single Activity launches UI; everything is foreground request/response.

---

## Threat model

**Defended:**
- Adversary with future quantum hardware reading captured archives
- Adversary with password but not PQ private key (when both set)
- Tampering with archive contents (GCM authentication detects any flip)
- Header swapping (GCM AAD binds header to ciphertext)
- Storage providers silently corrupting binary writes (read-back verification)
- Forensic recovery of decrypted scratch files (zeroed before delete)

**Not defended:**
- Compromised Android OS or kernel
- Hardware keyloggers or screen capture
- Coercion (rubber hose cryptanalysis)
- CPU-level side channels (mitigated only by constant-time guarantees of underlying primitives)

Zupt does NOT use Android Keystore for archive keys because the threat model is *file portability* — keys must travel with archives, not bind to devices.

---

## Reproducible builds

`.github/workflows/release.yml` is the canonical build. Any tagged release `v*` is built from clean checkout, signed with production keystore (from GitHub Secrets), APK + AAB attached to GitHub release with SHA-256 fingerprints. F-Droid rebuilds from source and verifies same artifacts.

Verify a release locally matches the official build:

```bash
git checkout v1.0.0
./gradlew :app:assembleRelease
sha256sum app/build/outputs/apk/release/app-release.apk
```

---

## License

**GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later).** See [`LICENSE`](LICENSE).

You can use, modify, and redistribute. Two conditions:

1. **Derivative works must remain AGPL-3.0** with source code available to anyone who has the binary
2. **If you make a modified version available over a network** (web service, hosted API, mobile backend), users interacting with it must be able to download the corresponding source. This closes the "SaaS loophole" present in plain GPL — relevant if anyone wraps Zupt's crypto core into a server product

Commercial use is allowed; closed proprietary forks are not. This matches the licensing of comparable privacy/security projects: Cryptomator, OnionShare, and Briar all use AGPL or GPL.

Bundled libraries:
- **BouncyCastle** — MIT-style (compatible with AGPL)
- **AndroidX Compose / Material 3** — Apache 2.0 (compatible with AGPL-3.0)
- **Kotlin standard library** — Apache 2.0

---

## Author

**Cristian Cezar Moisés** ([Security Ops](https://securityops.co))
- Email: sac@securityops.co · ethicalhacker@riseup.net
- LinkedIn: [linkedin.com/in/cristiancezarmoises](https://linkedin.com/in/cristiancezarmoises)
- Wiki: [wiki.securityops.co](https://wiki.securityops.co)
- Self-hosted git: [git.securityops.co](https://git.securityops.co)

> *Compress everything. Trust nothing. Encrypt always.*
