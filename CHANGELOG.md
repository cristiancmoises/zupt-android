# Changelog

All notable changes to Zupt for Android. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2026-04-25

Initial public release.

### Features

**Compression**
- Multi-file compression: pick any number of files into one `.zupt` archive
- Folder compression: recursively walk a directory tree, preserving relative paths
- Three codecs: DEFLATE (default), Brotli (better ratio), LZ4 (faster)
- Streaming I/O: memory use is O(1 MiB) regardless of file size — compress files larger than your RAM
- Per-file and per-block XXH64 integrity hashes
- Real-time progress display with phase indicators

**Encryption**
- Hybrid post-quantum KEM: ML-KEM-768 (NIST FIPS 203) combined with X25519 (RFC 7748) via SHAKE256 with domain separator `"ZUPT-HYB-v1"`
- AES-256-GCM authenticated encryption (FIPS 140-3 approved AEAD); 12-byte nonce, 16-byte tag, AAD binds the entire archive header to the ciphertext
- Password-based key derivation: PBKDF2-HMAC-SHA512 at 1,000,000 iterations, 32-byte salt
- Combined password+PQ mode: SHAKE256 mixes both keys with domain separator `"ZUPT-PWPQ-v1"` — recipient needs both to decrypt
- All sensitive buffers wiped via `Arrays.fill` in `finally` blocks
- Cryptographically strong RNG: `SecureRandom.getInstanceStrong()` cached lazily

**Privacy & security**
- Zero network code; `INTERNET` permission is not declared in the manifest
- Zero broad storage access; uses Storage Access Framework only — every file operation explicitly asks the user
- No telemetry, no analytics, no ads, no Google Play Services
- Save-and-verify: every file written is read back and byte-compared to detect storage providers that corrupt binary data
- Anti-forensic scratch wiping: temporary decryption files are zeroed via `RandomAccessFile.write(zeros)` + `fd.sync()` before deletion
- BouncyCastle PQC provider explicitly registered at `Application.onCreate()` to avoid R8 reflection-stripping issues
- KDF pinned to BC provider for cross-Android-version determinism; AES-GCM left to OS provider for Conscrypt's hardware acceleration

**UI**
- Compose Material 3 with cyan/magenta dark theme
- Six screens: Compress, Extract, Keys, Verify, Info, About
- Edge-to-edge layout, transparent system bars
- Single Activity, no services, no broadcast receivers, no content providers

**Build & distribution**
- AGPL-3.0-or-later license — closes the SaaS loophole that plain GPL leaves open
- Reproducible builds verified across Linux x86_64 and aarch64
- GitHub Actions CI: every push and PR builds unsigned APK + AAB with SHA-256 sums
- GitHub Actions release workflow: tags matching `v*` build, sign, verify with `apksigner`, and publish to GitHub Releases with auto-generated release notes from this CHANGELOG
- Fastlane metadata included for F-Droid

### Archive format

`zupt/v1.1` wire format. See [`SPEC.md`](SPEC.md) for the byte-level layout.

### Requirements

- Android 8.0 (API 26) or later
- ARM64, ARMv7, or x86_64

---

[1.0.0]: https://github.com/cristiancmoises/zupt-android/releases/tag/v1.0.0
