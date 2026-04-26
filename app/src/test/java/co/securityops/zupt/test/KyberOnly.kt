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
import java.security.SecureRandom
import java.security.Security
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.KeyAgreement
import javax.crypto.KeyGenerator
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation
import org.bouncycastle.jcajce.spec.KEMExtractSpec
import org.bouncycastle.jcajce.spec.KEMGenerateSpec
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec

fun main() {
    Security.insertProviderAt(BouncyCastleProvider(), 1)
    Security.insertProviderAt(BouncyCastlePQCProvider(), 2)

    println("=== KYBER alone ===")
    val kpg = KeyPairGenerator.getInstance("KYBER", "BCPQC")
    kpg.initialize(KyberParameterSpec.kyber768, SecureRandom())
    val kp = kpg.generateKeyPair()
    println("pub=${kp.public.encoded.size} priv=${kp.private.encoded.size}")

    // Encap
    val kgen = KeyGenerator.getInstance("KYBER", "BCPQC")
    kgen.init(KEMGenerateSpec(kp.public, "AES"))
    val gs = kgen.generateKey() as SecretKeyWithEncapsulation
    val ct = gs.encapsulation
    val ss1 = gs.encoded
    println("ct=${ct.size} ss1=${ss1.take(8).joinToString("") { "%02x".format(it) }}")

    // Decap using ORIGINAL private key object
    val kgen2 = KeyGenerator.getInstance("KYBER", "BCPQC")
    kgen2.init(KEMExtractSpec(kp.private, ct, "AES"))
    val ss2 = (kgen2.generateKey() as SecretKeyWithEncapsulation).encoded
    println("ss2 (orig)=${ss2.take(8).joinToString("") { "%02x".format(it) }} match=${ss1.contentEquals(ss2)}")

    // Decap using RECONSTRUCTED private key from PKCS#8
    val kf = KeyFactory.getInstance("KYBER", "BCPQC")
    val privReconstructed = kf.generatePrivate(PKCS8EncodedKeySpec(kp.private.encoded))
    val kgen3 = KeyGenerator.getInstance("KYBER", "BCPQC")
    kgen3.init(KEMExtractSpec(privReconstructed, ct, "AES"))
    val ss3 = (kgen3.generateKey() as SecretKeyWithEncapsulation).encoded
    println("ss3 (recon)=${ss3.take(8).joinToString("") { "%02x".format(it) }} match=${ss1.contentEquals(ss3)}")

    // Decap using RECONSTRUCTED public for encap
    val pubReconstructed = kf.generatePublic(X509EncodedKeySpec(kp.public.encoded))
    val kgen4 = KeyGenerator.getInstance("KYBER", "BCPQC")
    kgen4.init(KEMGenerateSpec(pubReconstructed, "AES"))
    val gs4 = kgen4.generateKey() as SecretKeyWithEncapsulation
    val ss1b = gs4.encoded
    val ctB = gs4.encapsulation
    val kgen5 = KeyGenerator.getInstance("KYBER", "BCPQC")
    kgen5.init(KEMExtractSpec(privReconstructed, ctB, "AES"))
    val ss2b = (kgen5.generateKey() as SecretKeyWithEncapsulation).encoded
    println("full-recon cycle: encap=${ss1b.take(8).joinToString(""){"%02x".format(it)}} decap=${ss2b.take(8).joinToString(""){"%02x".format(it)}} match=${ss1b.contentEquals(ss2b)}")
}
