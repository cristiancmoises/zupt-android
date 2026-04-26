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

import co.securityops.zupt.core.archive.StreamingReader
import co.securityops.zupt.core.archive.StreamingWriter
import co.securityops.zupt.core.codec.CodecId
import co.securityops.zupt.core.crypto.HybridKem
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.security.MessageDigest
import java.security.Security
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider

fun main() {
    Security.insertProviderAt(BouncyCastleProvider(), 1)
    Security.insertProviderAt(BouncyCastlePQCProvider(), 2)

    val scratchDir = File("/tmp/zupt-scratch").apply { mkdirs() }
    val kp = HybridKem.generateKeypair()
    val pw = "hunter2".toCharArray()

    // 50 MB payload with deterministic pattern for verification
    println("=== Test: 50 MiB file, pw+PQ, GCM streaming ===")
    val payloadSize = 50L * 1024 * 1024
    val payloadSha = streamRoundTrip(payloadSize, scratchDir, pw, kp)

    println("\n=== Test: 100 MiB file ===")
    streamRoundTrip(100L * 1024 * 1024, scratchDir, pw, kp)

    println("\n=== Test: 80 MiB INCOMPRESSIBLE (SecureRandom) — exercises full-archive-size path ===")
    streamRoundTripRandom(80L * 1024 * 1024, scratchDir, pw, kp)
}

private fun streamRoundTripRandom(
    size: Long, scratchDir: File, pw: CharArray, kp: HybridKem.HybridKeypair
) {
    val inputFile = File.createTempFile("zupt-input-rand-", ".bin", scratchDir)
    val archiveFile = File.createTempFile("zupt-archive-rand-", ".bin", scratchDir)
    val outputFile = File.createTempFile("zupt-output-rand-", ".bin", scratchDir)
    try {
        val sha = MessageDigest.getInstance("SHA-256")
        val rng = java.security.SecureRandom()
        inputFile.outputStream().buffered(256 * 1024).use { out ->
            val buf = ByteArray(32 * 1024)   // under BC DRBG 256KB/request limit
            var written = 0L
            while (written < size) {
                val n = minOf(buf.size.toLong(), size - written).toInt()
                rng.nextBytes(buf)
                out.write(buf, 0, n)
                sha.update(buf, 0, n)
                written += n
            }
        }
        val inHex = sha.digest().joinToString("") { "%02x".format(it) }
        println("  input sha256 = ${inHex.take(16)}…")

        inputFile.inputStream().use { inp ->
            archiveFile.outputStream().use { out ->
                co.securityops.zupt.core.archive.StreamingWriter.write(
                    inp, out, scratchDir,
                    co.securityops.zupt.core.archive.StreamingWriter.Options(
                        codec = co.securityops.zupt.core.codec.CodecId.DEFLATE, level = 3,
                        password = pw.copyOf(),
                        pqRecipientPublic = kp.publicKey,
                        fileName = inputFile.name, fileSize = size
                    )
                )
            }
        }
        println("  compress: ${archiveFile.length()} B")

        archiveFile.inputStream().use { inp ->
            outputFile.outputStream().use { out ->
                co.securityops.zupt.core.archive.StreamingReader.extract(
                    inp, archiveFile.length(), out, scratchDir,
                    password = pw.copyOf(), hybridPriv = kp.privateKey
                )
            }
        }

        val outSha = MessageDigest.getInstance("SHA-256")
        outputFile.inputStream().buffered(256 * 1024).use { inp ->
            val buf = ByteArray(64 * 1024)
            while (true) {
                val n = inp.read(buf); if (n <= 0) break
                outSha.update(buf, 0, n)
            }
        }
        val outHex = outSha.digest().joinToString("") { "%02x".format(it) }
        val match = inHex == outHex
        println("  output sha256 = ${outHex.take(16)}…  match=$match")
        if (!match) error("RANDOM HASH MISMATCH")
    } finally {
        inputFile.delete(); archiveFile.delete(); outputFile.delete()
    }
}

private fun streamRoundTrip(
    size: Long, scratchDir: File, pw: CharArray, kp: HybridKem.HybridKeypair
): String {
    val inputFile = File.createTempFile("zupt-input-", ".bin", scratchDir)
    val archiveFile = File.createTempFile("zupt-archive-", ".bin", scratchDir)
    val outputFile = File.createTempFile("zupt-output-", ".bin", scratchDir)
    try {
        // Generate deterministic payload on disk
        val sha = MessageDigest.getInstance("SHA-256")
        inputFile.outputStream().buffered(256 * 1024).use { out ->
            val buf = ByteArray(64 * 1024)
            var written = 0L
            var counter = 0
            while (written < size) {
                val n = minOf(buf.size.toLong(), size - written).toInt()
                for (i in 0 until n) {
                    buf[i] = ((counter++) and 0xFF).toByte()
                }
                out.write(buf, 0, n)
                sha.update(buf, 0, n)
                written += n
            }
        }
        val inHex = sha.digest().joinToString("") { "%02x".format(it) }
        println("  input sha256 = ${inHex.take(16)}…")

        // Compress
        val t0 = System.currentTimeMillis()
        val result = inputFile.inputStream().use { inp ->
            archiveFile.outputStream().use { out ->
                StreamingWriter.write(
                    inp, out, scratchDir,
                    StreamingWriter.Options(
                        codec = CodecId.DEFLATE, level = 6,
                        password = pw.copyOf(),
                        pqRecipientPublic = kp.publicKey,
                        fileName = inputFile.name,
                        fileSize = size
                    )
                )
            }
        }
        val t1 = System.currentTimeMillis()
        val compressMB = size / 1024.0 / 1024.0 / ((t1 - t0) / 1000.0)
        println("  compress: ${archiveFile.length()} B, ${"%.2f".format(result.ratio)} ratio, %.1f MB/s".format(compressMB))

        // Extract
        val t2 = System.currentTimeMillis()
        val entry = archiveFile.inputStream().use { inp ->
            outputFile.outputStream().use { out ->
                StreamingReader.extract(
                    inp, archiveFile.length(), out, scratchDir,
                    password = pw.copyOf(), hybridPriv = kp.privateKey
                )
            }
        }
        val t3 = System.currentTimeMillis()
        val extractMB = size / 1024.0 / 1024.0 / ((t3 - t2) / 1000.0)
        println("  extract: $entry ${outputFile.length()} B, %.1f MB/s".format(extractMB))

        // Verify by sha256
        val outSha = MessageDigest.getInstance("SHA-256")
        outputFile.inputStream().buffered(256 * 1024).use { inp ->
            val buf = ByteArray(64 * 1024)
            while (true) {
                val n = inp.read(buf)
                if (n <= 0) break
                outSha.update(buf, 0, n)
            }
        }
        val outHex = outSha.digest().joinToString("") { "%02x".format(it) }
        val match = inHex == outHex
        println("  output sha256 = ${outHex.take(16)}…  match=$match")
        if (!match) error("HASH MISMATCH")
        return inHex
    } finally {
        inputFile.delete()
        archiveFile.delete()
        outputFile.delete()
    }
}
