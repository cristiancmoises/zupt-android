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
package co.securityops.zupt.test

import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.Security
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.KeyAgreement
import org.bouncycastle.jce.provider.BouncyCastleProvider

fun main() {
    Security.insertProviderAt(BouncyCastleProvider(), 1)

    val kpg = KeyPairGenerator.getInstance("X25519", "BC")
    val kp = kpg.generateKeyPair()

    val pubEnc = kp.public.encoded
    val privEnc = kp.private.encoded
    println("X25519 pub encoded: ${pubEnc.size} B, hex: ${pubEnc.joinToString("") { "%02x".format(it) }}")
    println("X25519 priv encoded: ${privEnc.size} B, hex: ${privEnc.joinToString("") { "%02x".format(it) }}")

    // "Raw" by my extractor logic: last 32 bytes
    val rawPrivLast32 = privEnc.copyOfRange(privEnc.size - 32, privEnc.size)
    println("last 32 of priv: ${rawPrivLast32.joinToString("") { "%02x".format(it) }}")

    // Proper extraction: find innermost OCTET STRING
    // The PKCS#8 structure for X25519: 30 2e 02 01 00 30 05 06 03 2b 65 6e 04 22 04 20 <32 bytes>
    // So raw is at offset 16, length 32
    val rawPrivProper = privEnc.copyOfRange(16, 16 + 32)
    println("proper raw priv: ${rawPrivProper.joinToString("") { "%02x".format(it) }}")
    println("match? ${rawPrivLast32.contentEquals(rawPrivProper)}")

    // Test: reconstruct wrapper + see if ECDH gives same result as original
    val prefix = byteArrayOf(
        0x30, 0x2E, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x6E, 0x04, 0x22, 0x04, 0x20
    )
    val rewrappedPriv = prefix + rawPrivProper
    println("rewrapped priv: ${rewrappedPriv.size}B, match original priv? ${rewrappedPriv.contentEquals(privEnc)}")

    val kf = KeyFactory.getInstance("X25519", "BC")
    val reconPriv = kf.generatePrivate(PKCS8EncodedKeySpec(rewrappedPriv))

    // Reproduce ECDH with original private & reconstructed private
    val kp2 = kpg.generateKeyPair()
    val ka1 = KeyAgreement.getInstance("X25519", "BC")
    ka1.init(kp.private)
    ka1.doPhase(kp2.public, true)
    val ss1 = ka1.generateSecret()

    val ka2 = KeyAgreement.getInstance("X25519", "BC")
    ka2.init(reconPriv)
    ka2.doPhase(kp2.public, true)
    val ss2 = ka2.generateSecret()

    println("ECDH with orig priv:  ${ss1.joinToString("") { "%02x".format(it) }}")
    println("ECDH with recon priv: ${ss2.joinToString("") { "%02x".format(it) }}")
    println("match? ${ss1.contentEquals(ss2)}")
}
