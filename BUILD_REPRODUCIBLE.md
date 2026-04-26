# Reproducible builds

Zupt's release artifacts are built deterministically. Anyone with the source tree at a tagged commit and the same toolchain versions can produce a byte-identical APK.

## Verifying a release

1. Download the signed APK from [GitHub Releases](https://github.com/cristiancmoises/zupt-android/releases) and the matching `SHA256SUMS.txt`.
2. Verify the APK signature:
   ```bash
   apksigner verify --print-certs zupt-vX.Y.Z.apk
   ```
   The certificate fingerprint should match the one published in the repo (`docs/signing-cert.pem` SHA-256).
3. Verify SHA-256:
   ```bash
   sha256sum zupt-vX.Y.Z.apk
   # Compare to the entry in SHA256SUMS.txt
   ```

## Building from source for verification

```bash
git clone https://github.com/cristiancmoises/zupt-android
cd zupt-android
git checkout vX.Y.Z

# Use exactly the same JDK + SDK versions
export JAVA_HOME=$(asdf where java temurin-21.0.5+11)  # or your equivalent
export ANDROID_HOME=$HOME/Android/Sdk

./gradlew :app:assembleRelease

# Compare unsigned APK
sha256sum app/build/outputs/apk/release/app-release-unsigned.apk
```

The unsigned APK should match across machines bit-for-bit. The signed release APK additionally embeds the signature block, which differs based on the signing certificate but the signed APK content is otherwise identical when re-signed with the same key.

## Toolchain pinning

| Tool | Version | Why |
|---|---|---|
| JDK | Temurin 21 | latest LTS; Kotlin 2.0 supports it |
| Android Gradle Plugin | 8.5.2 | matches CI |
| Kotlin | 2.0.21 | matches CI |
| compileSdk | 34 | Android 14 |
| minSdk | 26 | Android 8.0+ |
| Gradle | 8.7 | per `gradle/wrapper/gradle-wrapper.properties` |

These are pinned in `app/build.gradle.kts` and verified by CI on every push.

## CI build infrastructure

`.github/workflows/build.yml` builds every push and PR against:
- ubuntu-latest (currently Ubuntu 24.04 LTS)
- Temurin JDK 21
- AGP 8.5.2 + bundled `cmdline-tools`

`.github/workflows/release.yml` is triggered only by tags matching `v*`. It:
1. Extracts version from tag (e.g. `v1.0.0` → `1.0.0`)
2. Verifies that `versionName` in `app/build.gradle.kts` matches the tag (fails if mismatched — prevents accidental tag/code drift)
3. Decodes the production keystore from `secrets.ZUPT_KEYSTORE_BASE64`
4. Signs APK + AAB using credentials from secrets
5. Verifies signature with `apksigner verify`
6. Generates SHA-256 sums
7. Extracts release notes from `CHANGELOG.md` (section matching version)
8. Creates GitHub release with all artifacts attached

## Setting up secrets (maintainer notes)

For the release workflow to work, the maintainer must set these GitHub repo secrets:

| Secret | Value |
|---|---|
| `ZUPT_KEYSTORE_BASE64` | `base64 -w0 < zupt-release.keystore` |
| `ZUPT_KS_PASS` | keystore password |
| `ZUPT_KS_ALIAS` | key alias |
| `ZUPT_KS_KEY_PASS` | key password (often same as keystore password) |

```bash
# Generate a production keystore (do this OFFLINE, on an air-gapped machine if possible)
keytool -genkey -v -keystore zupt-release.keystore \
  -keyalg RSA -keysize 4096 -validity 10000 -alias zupt \
  -dname "CN=Cristian Cezar Moises, O=Security Ops, C=BR"

# Encode for GitHub Secret
base64 -w0 < zupt-release.keystore | xclip -selection clipboard

# Store the keystore itself in your password manager. NEVER commit it.
# NEVER add it to .gradle/ or app/.
```

The keystore in this repo (`zupt-release.keystore` — gitignored) is a development fixture only. F-Droid will sign with their own infrastructure; this signing path is for direct-download distribution.
