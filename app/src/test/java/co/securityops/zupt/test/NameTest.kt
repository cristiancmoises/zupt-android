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

import co.securityops.zupt.core.archive.ArchiveReader
import co.securityops.zupt.core.archive.ArchiveWriter
import co.securityops.zupt.core.codec.CodecId
import co.securityops.zupt.core.crypto.HybridKem
import java.security.Security
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider

fun main() {
    Security.insertProviderAt(BouncyCastleProvider(), 1)
    Security.insertProviderAt(BouncyCastlePQCProvider(), 2)

    val payload = ByteArray(3000) { (it % 251).toByte() }
    val kp = HybridKem.generateKeypair()
    val pw = "hunter2".toCharArray()

    println("=== Test A: simple name 'test.bin' ===")
    testName(payload, "test.bin", pw, kp)

    println("\n=== Test B: name with spaces 'my file.bin' ===")
    testName(payload, "my file.bin", pw, kp)

    println("\n=== Test C: name with unicode 'résumé café.txt' ===")
    testName(payload, "résumé café.txt", pw, kp)

    println("\n=== Test D: very long name (500 chars) ===")
    testName(payload, "a".repeat(500) + ".bin", pw, kp)

    println("\n=== Test E: empty name '' ===")
    testName(payload, "", pw, kp)

    println("\n=== Test F: name with slash 'dir/file.bin' ===")
    testName(payload, "dir/file.bin", pw, kp)

    println("\n=== Test G: name with .zupt extension 'test.bin.zupt' ===")
    testName(payload, "test.bin.zupt", pw, kp)

    println("\n=== Test H: name with newline 'bad\\nname' ===")
    testName(payload, "bad\nname", pw, kp)

    println("\n=== Test I: only extension '.bin' ===")
    testName(payload, ".bin", pw, kp)
}

private fun testName(payload: ByteArray, name: String, pw: CharArray, kp: HybridKem.HybridKeypair) {
    try {
        val result = ArchiveWriter.write(
            ArchiveWriter.Input(name, payload),
            ArchiveWriter.Options(
                codec = CodecId.DEFLATE, level = 6,
                password = pw.copyOf(),
                pqRecipientPublic = kp.publicKey
            )
        )
        val (entry, extracted) = ArchiveReader.extract(
            result.bytes, password = pw.copyOf(), hybridPriv = kp.privateKey
        )
        val ok = extracted.contentEquals(payload)
        println("  archive=${result.bytes.size}B entry.path='${entry.path}' match=$ok")
    } catch (t: Throwable) {
        println("  FAIL: ${t.javaClass.simpleName}: ${t.message}")
    }
}
