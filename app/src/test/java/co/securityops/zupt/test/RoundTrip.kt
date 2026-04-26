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
// Round-trip test: generate keys → compress → extract → compare bytes
// This is the EXACT code path the app uses. Run from JVM to isolate the bug.
package co.securityops.zupt.test

import co.securityops.zupt.core.archive.ArchiveReader
import co.securityops.zupt.core.archive.ArchiveWriter
import co.securityops.zupt.core.codec.CodecId
import co.securityops.zupt.core.crypto.HybridKem
import co.securityops.zupt.util.toHex
import java.security.Security
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider

fun main() {
    Security.insertProviderAt(BouncyCastleProvider(), 1)
    Security.insertProviderAt(BouncyCastlePQCProvider(), 2)

    val payload = ByteArray(3000) { (it % 251).toByte() }
    println("INPUT:     ${payload.size} B")

    println("\n[1] Password-only")
    roundTrip(payload, "hunter2".toCharArray(), null)

    println("\n[2] PQ-only")
    val kp = HybridKem.generateKeypair()
    println("  pub=${kp.publicKey.size}B priv=${kp.privateKey.size}B")
    roundTrip(payload, null, kp)

    println("\n[3] Password + PQ")
    roundTrip(payload, "hunter2".toCharArray(), kp)

    println("\n[4] No encryption")
    roundTrip(payload, null, null)

    println("\nALL GOOD")
}

private fun roundTrip(
    payload: ByteArray,
    pw: CharArray?,
    kp: HybridKem.HybridKeypair?
) {
    // DIAGNOSTIC: manually exercise encapsulate/decapsulate
    if (kp != null && pw == null) {
        val encap = HybridKem.encapsulate(kp.publicKey)
        val decap = HybridKem.decapsulate(kp.privateKey, encap.ciphertext)
        val match = encap.sharedSecret.contentEquals(decap)
        println("  KEM: encap.ss=${encap.sharedSecret.toHex().take(32)}…")
        println("  KEM: decap.ss=${decap.toHex().take(32)}…")
        println("  KEM direct match: $match")
    }

    val result = ArchiveWriter.write(
        ArchiveWriter.Input("test.bin", payload),
        ArchiveWriter.Options(
            codec = CodecId.DEFLATE,
            level = 6,
            password = pw?.copyOf(),
            pqRecipientPublic = kp?.publicKey
        )
    )
    println("  archive=${result.bytes.size}B blocks=${result.blockCount}")

    try {
        val (entry, extracted) = ArchiveReader.extract(
            result.bytes,
            password = pw?.copyOf(),
            hybridPriv = kp?.privateKey
        )
        val match = extracted.contentEquals(payload)
        println("  extracted=${extracted.size}B name=${entry.path} match=$match")
        if (!match) error("BYTE MISMATCH")
    } catch (t: Throwable) {
        println("  FAIL: ${t.javaClass.simpleName}: ${t.message}")
        t.printStackTrace(System.out)
        error("extraction failed")
    }
}
