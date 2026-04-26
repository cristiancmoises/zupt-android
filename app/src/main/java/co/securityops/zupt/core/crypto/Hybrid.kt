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

import org.bouncycastle.crypto.digests.SHAKEDigest
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation
import org.bouncycastle.jcajce.spec.KEMExtractSpec
import org.bouncycastle.jcajce.spec.KEMGenerateSpec
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Security
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.KeyAgreement
import javax.crypto.KeyGenerator

/**
 * Hybrid post-quantum key encapsulation:
 *   ML-KEM-768 (FIPS 203) ⊕ X25519 (RFC 7748)
 *
 * Produces a single 64-byte shared secret via
 *   SHAKE256(mlkem_ss ‖ x25519_ss ‖ "ZUPT-HYB-v1") → 64 B.
 *
 * Wire format for encapsulation blob:
 *   [ mlkem_ct : 1088 B ][ x25519_ephemeral_pub : 32 B ] = 1120 B
 *
 * Wire format for public key:  [ mlkem_pub : 1184 B ][ x25519_pub : 32 B ] = 1216 B
 * Wire format for private key: [ mlkem_priv : 2400 B ][ x25519_priv : 32 B ] = 2432 B
 */
object HybridKem {
    init {
        if (Security.getProvider("BC") == null) Security.addProvider(BouncyCastleProvider())
        if (Security.getProvider("BCPQC") == null) Security.addProvider(BouncyCastlePQCProvider())
    }

    const val MLKEM_PUB = 1184
    const val MLKEM_PRIV = 2400
    const val MLKEM_CT = 1088
    const val X_PUB = 32
    const val X_PRIV = 32

    const val HYBRID_PUB = MLKEM_PUB + X_PUB       // 1216
    const val HYBRID_PRIV = MLKEM_PRIV + X_PRIV    // 2432
    const val HYBRID_CT = MLKEM_CT + X_PUB         // 1120
    const val SHARED_SECRET_BYTES = 64
    private val HYBRID_INFO = "ZUPT-HYB-v1".toByteArray(Charsets.US_ASCII)

    data class HybridKeypair(val publicKey: ByteArray, val privateKey: ByteArray)
    data class Encapsulation(val ciphertext: ByteArray, val sharedSecret: ByteArray)

    fun generateKeypair(): HybridKeypair {
        val rng = try { SecureRandom.getInstanceStrong() } catch (_: Throwable) { SecureRandom() }
        // ML-KEM-768
        val kpg = KeyPairGenerator.getInstance("KYBER", "BCPQC")
        kpg.initialize(KyberParameterSpec.kyber768, rng)
        val mlkemKp: KeyPair = kpg.generateKeyPair()
        val mlkemPub = mlkemKp.public.encoded  // X.509 SubjectPublicKeyInfo
        val mlkemPriv = mlkemKp.private.encoded // PKCS#8

        // X25519
        val xkg = KeyPairGenerator.getInstance("X25519", "BC")
        xkg.initialize(255, rng)
        val xkp: KeyPair = xkg.generateKeyPair()
        val xPubRaw = extractX25519RawPublic(xkp.public.encoded)
        val xPrivRaw = extractX25519RawPrivate(xkp.private.encoded)

        // We store ML-KEM keys in their full BC-encoded form plus a 4-byte length prefix
        // so we can reconstruct them on decap. X25519 is always 32 B raw.
        val pub = packLenPrefixed(mlkemPub) + xPubRaw
        val priv = packLenPrefixed(mlkemPriv) + xPrivRaw
        try {
            return HybridKeypair(pub.copyOf(), priv.copyOf())
        } finally {
            // Wipe local copies of raw secret material that we passed into pack
            xPrivRaw.wipe()
            // mlkemPriv is the encoded form — also sensitive; wipe before returning
            java.util.Arrays.fill(mlkemPriv, 0.toByte())
        }
    }

    /** Sender side: encapsulate to a recipient's public key. */
    fun encapsulate(hybridPub: ByteArray): Encapsulation {
        val (mlkemPubEnc, xPubRaw) = unpackPublic(hybridPub)

        // ML-KEM encap
        val mlkemPub = KeyFactory.getInstance("KYBER", "BCPQC")
            .generatePublic(X509EncodedKeySpec(mlkemPubEnc))
        val kgen = KeyGenerator.getInstance("KYBER", "BCPQC")
        kgen.init(KEMGenerateSpec(mlkemPub, "AES"))
        val kSec = kgen.generateKey() as SecretKeyWithEncapsulation
        val mlkemCt = kSec.encapsulation
        var mlkemSS: ByteArray? = kSec.encoded

        // X25519 ephemeral + ECDH
        val xkg = KeyPairGenerator.getInstance("X25519", "BC")
        val ephKp = xkg.generateKeyPair()
        val ephPubRaw = extractX25519RawPublic(ephKp.public.encoded)

        val recipientXPub = KeyFactory.getInstance("X25519", "BC")
            .generatePublic(X509EncodedKeySpec(wrapX25519RawPublic(xPubRaw)))
        val ka = KeyAgreement.getInstance("X25519", "BC")
        ka.init(ephKp.private)
        ka.doPhase(recipientXPub, true)
        var xSS: ByteArray? = ka.generateSecret()

        try {
            val sharedSecret = shakeCombine(mlkemSS!!, xSS!!)
            return Encapsulation(mlkemCt + ephPubRaw, sharedSecret)
        } finally {
            mlkemSS?.wipe(); xSS?.wipe()
        }
    }

    /** Recipient side: decapsulate using private key + received blob. */
    fun decapsulate(hybridPriv: ByteArray, blob: ByteArray): ByteArray {
        require(blob.size == HYBRID_CT) { "Encapsulation blob must be $HYBRID_CT bytes" }
        val (mlkemPrivEnc, xPrivRaw) = unpackPrivate(hybridPriv)
        var mlkemSS: ByteArray? = null
        var xSS: ByteArray? = null
        try {
            val mlkemCt = blob.copyOfRange(0, MLKEM_CT)
            val ephXPubRaw = blob.copyOfRange(MLKEM_CT, HYBRID_CT)

            val mlkemPriv: PrivateKey = KeyFactory.getInstance("KYBER", "BCPQC")
                .generatePrivate(PKCS8EncodedKeySpec(mlkemPrivEnc))
            val kgen = KeyGenerator.getInstance("KYBER", "BCPQC")
            kgen.init(KEMExtractSpec(mlkemPriv, mlkemCt, "AES"))
            mlkemSS = (kgen.generateKey() as SecretKeyWithEncapsulation).encoded

            val xPriv: PrivateKey = KeyFactory.getInstance("X25519", "BC")
                .generatePrivate(PKCS8EncodedKeySpec(wrapX25519RawPrivate(xPrivRaw)))
            val ephPub: PublicKey = KeyFactory.getInstance("X25519", "BC")
                .generatePublic(X509EncodedKeySpec(wrapX25519RawPublic(ephXPubRaw)))
            val ka = KeyAgreement.getInstance("X25519", "BC")
            ka.init(xPriv)
            ka.doPhase(ephPub, true)
            xSS = ka.generateSecret()

            return shakeCombine(mlkemSS, xSS)
        } finally {
            mlkemSS?.wipe()
            xSS?.wipe()
            xPrivRaw.wipe()
            java.util.Arrays.fill(mlkemPrivEnc, 0.toByte())
        }
    }

    // ─── helpers ──────────────────────────────────────────────────────────

    private fun shakeCombine(a: ByteArray, b: ByteArray): ByteArray {
        val shake = SHAKEDigest(256)
        shake.update(a, 0, a.size)
        shake.update(b, 0, b.size)
        shake.update(HYBRID_INFO, 0, HYBRID_INFO.size)
        val out = ByteArray(SHARED_SECRET_BYTES)
        shake.doFinal(out, 0, SHARED_SECRET_BYTES)
        return out
    }

    private fun packLenPrefixed(b: ByteArray): ByteArray {
        val out = ByteArray(4 + b.size)
        out[0] = (b.size ushr 24).toByte()
        out[1] = (b.size ushr 16).toByte()
        out[2] = (b.size ushr 8).toByte()
        out[3] = b.size.toByte()
        System.arraycopy(b, 0, out, 4, b.size)
        return out
    }

    private fun readLenPrefixed(b: ByteArray, off: Int): Pair<ByteArray, Int> {
        val len = ((b[off].toInt() and 0xFF) shl 24) or
                ((b[off+1].toInt() and 0xFF) shl 16) or
                ((b[off+2].toInt() and 0xFF) shl 8) or
                (b[off+3].toInt() and 0xFF)
        val data = b.copyOfRange(off + 4, off + 4 + len)
        return data to (off + 4 + len)
    }

    private fun unpackPublic(hybridPub: ByteArray): Pair<ByteArray, ByteArray> {
        val (mlkem, next) = readLenPrefixed(hybridPub, 0)
        val x = hybridPub.copyOfRange(next, next + X_PUB)
        return mlkem to x
    }

    private fun unpackPrivate(hybridPriv: ByteArray): Pair<ByteArray, ByteArray> {
        val (mlkem, next) = readLenPrefixed(hybridPriv, 0)
        val x = hybridPriv.copyOfRange(next, next + X_PRIV)
        return mlkem to x
    }

    // X25519 raw 32-byte key <-> X.509 / PKCS#8 wrapping (RFC 8410).
    //
    // Public  X.509 (44 B):  30 2A 30 05 06 03 2B 65 6E 03 21 00 <32 raw>
    //                        └─ prefix (12 B) ─┘
    //
    // Private PKCS#8 (48 B, minimal): 30 2E 02 01 00 30 05 06 03 2B 65 6E 04 22 04 20 <32 raw>
    //                                 └──────── prefix (16 B) ────────┘
    //
    // BouncyCastle actually emits an 83-byte PKCS#8 for X25519 with the public
    // key attached as attribute [1] — we MUST NOT trust "last 32 bytes" for the
    // raw private scalar. Always read from offset 16 for length 32.
    private val X_PUB_PREFIX = byteArrayOf(
        0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x6E, 0x03, 0x21, 0x00
    )
    private val X_PRIV_PREFIX = byteArrayOf(
        0x30, 0x2E, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x6E, 0x04, 0x22, 0x04, 0x20
    )
    private const val X_RAW_LEN = 32
    private const val X_PUB_PREFIX_LEN = 12
    private const val X_PRIV_PREFIX_LEN = 16

    /** Extract raw 32-byte public from X.509 encoding (raw key is always the last 32 B). */
    private fun extractX25519RawPublic(encoded: ByteArray): ByteArray {
        require(encoded.size == X_PUB_PREFIX_LEN + X_RAW_LEN) {
            "X25519 X.509 public must be ${X_PUB_PREFIX_LEN + X_RAW_LEN}B, got ${encoded.size}"
        }
        return encoded.copyOfRange(X_PUB_PREFIX_LEN, X_PUB_PREFIX_LEN + X_RAW_LEN)
    }

    /**
     * Extract raw 32-byte private from PKCS#8 encoding.
     * CRITICAL: read at fixed offset X_PRIV_PREFIX_LEN, NOT from the tail, because
     * BC appends the public key as an optional attribute after the raw private.
     */
    private fun extractX25519RawPrivate(encoded: ByteArray): ByteArray {
        require(encoded.size >= X_PRIV_PREFIX_LEN + X_RAW_LEN) {
            "X25519 PKCS#8 too short: ${encoded.size}B"
        }
        return encoded.copyOfRange(X_PRIV_PREFIX_LEN, X_PRIV_PREFIX_LEN + X_RAW_LEN)
    }

    private fun wrapX25519RawPublic(raw: ByteArray): ByteArray {
        require(raw.size == X_RAW_LEN) { "X25519 raw pub must be ${X_RAW_LEN}B" }
        return X_PUB_PREFIX + raw
    }

    private fun wrapX25519RawPrivate(raw: ByteArray): ByteArray {
        require(raw.size == X_RAW_LEN) { "X25519 raw priv must be ${X_RAW_LEN}B" }
        return X_PRIV_PREFIX + raw
    }
}
