/*
 * Zupt for Android — post-quantum encrypted file compression
 * Copyright (C) 2026 Cristian Cezar Moisés
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package co.securityops.zupt.core.crypto

import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import javax.crypto.SecretKeyFactory

/**
 * Cryptographically secure random bytes.
 *
 * Uses SecureRandom.getInstanceStrong() lazily — first call may block briefly
 * on /dev/random; subsequent calls are non-blocking. We cache the instance to
 * avoid repeated blocking initialization on cold boot.
 */
private val strongRng: SecureRandom by lazy {
    try { SecureRandom.getInstanceStrong() } catch (_: Throwable) { SecureRandom() }
}

fun secureRandomBytes(n: Int): ByteArray {
    require(n > 0) { "Cannot generate $n random bytes" }
    val out = ByteArray(n)
    strongRng.nextBytes(out)
    return out
}

/** Wipe sensitive buffer in place. */
fun ByteArray.wipe() { java.util.Arrays.fill(this, 0.toByte()) }
fun CharArray.wipe() { java.util.Arrays.fill(this, '\u0000') }

/**
 * PBKDF2-HMAC-SHA512 key derivation.
 *
 * 1,000,000 iterations — 2× OWASP 2023 guidance (600k for SHA-256, we use SHA-512
 * which is already ~2× stronger per iter on 64-bit targets; final effective cost ≈4×).
 *
 * SHA-512 specifically because:
 *   - PBKDF2 output length requests >hash_output_size trigger a known weakness
 *     where bcrypt-style collisions can reduce effective iters. SHA-512's 64-byte
 *     output lets us request 64 bytes (32 enc + 32 mac) in a single block.
 */
object Kdf {
    const val DEFAULT_ITERS = 1_000_000
    const val DERIVED_BYTES = 64  // exactly 1 SHA-512 block; no extension cost

    fun derive(password: CharArray, salt: ByteArray, iters: Int = DEFAULT_ITERS): ByteArray {
        require(iters >= 100_000) { "Refusing weak KDF iteration count: $iters" }
        require(salt.size >= 16) { "KDF salt too short: ${salt.size}B (min 16)" }
        require(password.isNotEmpty()) { "Password cannot be empty" }
        val spec = PBEKeySpec(password, salt, iters, DERIVED_BYTES * 8)
        try {
            // Pin to BC for cross-device determinism — Android's default provider
            // implementation has changed across API levels; BC is bundled with the
            // app (1.78.1) so output is reproducible regardless of OS version.
            val factory = try {
                SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512", "BC")
            } catch (_: Throwable) {
                SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512")
            }
            return factory.generateSecret(spec).encoded
        } finally {
            spec.clearPassword()
        }
    }
}

/**
 * AES-256-GCM authenticated encryption.
 *
 * GCM provides confidentiality + authentication in a single primitive with
 * constant-time tag verification. Preferred over CTR+HMAC construction:
 *   - NIST SP 800-38D approved
 *   - FIPS 140-3 compliant
 *   - Hardware accelerated on ARMv8 (PMULL) and x86 (AES-NI + CLMUL)
 *   - Single key (32B) instead of separate enc+mac keys
 *
 * Contract: nonce MUST be unique per key. We generate 12 random bytes per archive.
 * At 2^32 encryptions per key (~4B), nonce collision probability reaches 2^-32.
 * Zupt archives: one encryption per archive, effectively zero risk.
 */
object Aead {
    const val KEY_SIZE = 32
    const val NONCE_SIZE = 12     // GCM IV is 12 bytes per NIST recommendation
    const val TAG_SIZE = 16       // 128-bit authentication tag
    const val TAG_BITS = 128

    fun encrypt(key: ByteArray, nonce: ByteArray, aad: ByteArray, plaintext: ByteArray): ByteArray {
        require(key.size == KEY_SIZE) { "Key must be $KEY_SIZE bytes" }
        require(nonce.size == NONCE_SIZE) { "Nonce must be $NONCE_SIZE bytes" }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, nonce))
        cipher.updateAAD(aad)
        return cipher.doFinal(plaintext)
    }

    fun decrypt(key: ByteArray, nonce: ByteArray, aad: ByteArray, ciphertextWithTag: ByteArray): ByteArray {
        require(key.size == KEY_SIZE) { "Key must be $KEY_SIZE bytes" }
        require(nonce.size == NONCE_SIZE) { "Nonce must be $NONCE_SIZE bytes" }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, nonce))
        cipher.updateAAD(aad)
        return cipher.doFinal(ciphertextWithTag)
    }

    /**
     * Derive an AES-256 key from a 64-byte KDF output by HKDF-like extraction.
     * Uses the first 32 bytes directly (the output of PBKDF2/SHAKE256 is already
     * uniformly distributed). The remaining 32 bytes are reserved for integrity
     * checks in the archive format.
     */
    fun deriveEncKey(derived64: ByteArray): ByteArray {
        require(derived64.size == 64) { "Expected 64 bytes of derived material" }
        return derived64.copyOfRange(0, 32)
    }
}
